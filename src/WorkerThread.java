// WorkerThread.java
//
// Runs as its own thread. Pulls Packet objects off the input queue,
// does the real DPI work (parse headers, extract SNI, look up/update
// the flow, check blocking rules), then pushes the now-fully-processed
// Packet onto the output queue for the Writer thread.
//
// Multiple WorkerThreads can run at once, each pulling from the SAME
// input queue - the queue automatically makes sure each packet only
// goes to ONE worker (they never compete for the same packet).

import java.util.concurrent.BlockingQueue;

public class WorkerThread extends Thread {

    private final BlockingQueue<Packet> inputQueue;
    private final BlockingQueue<Packet> outputQueue;
    private final FlowTracker tracker;  // SHARED across all worker threads
    private final RuleManager rules;    // SHARED - read-only after setup, so safe

    public WorkerThread(String name, BlockingQueue<Packet> inputQueue,
                         BlockingQueue<Packet> outputQueue,
                         FlowTracker tracker, RuleManager rules) {
        super(name);
        this.inputQueue = inputQueue;
        this.outputQueue = outputQueue;
        this.tracker = tracker;
        this.rules = rules;
    }

    @Override
    public void run() {
        int processedCount = 0;

        while (true) {
            Packet pkt;
            try {
                pkt = inputQueue.take(); // blocks until a packet is available
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }

            if (pkt instanceof PoisonPill) {
                // IMPORTANT: forward the poison pill onward to the Writer thread too!
                // If we just `break` here without forwarding, the Writer will wait
                // forever for a poison pill that never arrives - this caused a hang.
                try {
                    outputQueue.put(pkt);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                break; // this worker is done - no more packets coming
            }

            processPacket(pkt);
            processedCount++;

            try {
                outputQueue.put(pkt); // hand off to the Writer thread
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
        }

        System.out.println("[" + getName() + "] finished - processed " + processedCount + " packets");
    }

    // This is exactly the same logic from our single-threaded Main.java,
    // just moved here so multiple threads can run it concurrently.
    private void processPacket(Packet pkt) {
        ParsedPacket parsed = PacketParser.parse(pkt.raw);
        pkt.parsed = parsed;

        if (parsed == null) {
            pkt.blocked = false; // can't identify it - let it through, same as before
            return;
        }

        FiveTuple key = new FiveTuple(
                Integer.toUnsignedLong(parsed.srcIp),
                Integer.toUnsignedLong(parsed.dstIp),
                parsed.srcPort,
                parsed.dstPort,
                parsed.isTcp ? 6 : 17);

        Flow flow = tracker.getOrCreateFlow(key); // thread-safe (synchronized inside)

        // CRITICAL: everything that reads or writes fields ON this specific
        // Flow object (packetCount, sni, blocked) must be synchronized on
        // that Flow - otherwise two worker threads handling two different
        // packets of the SAME connection can race each other. This caused
        // a real bug during testing: one thread would check `flow.blocked`
        // a split second before another thread finished setting it to true,
        // letting a packet through that should have been dropped.
        synchronized (flow) {
            flow.packetCount++;

            if (flow.sni == null && parsed.isTcp && parsed.dstPort == 443) {
                String hostname = SniExtractor.extract(parsed.payload);
                if (hostname != null) {
                    // Set the flow's fields directly instead of calling
                    // tracker.recordSni() here - that method is itself
                    // `synchronized` on the FlowTracker, and calling it
                    // while we're already holding this flow's lock means
                    // we'd be holding TWO locks at once, in a fixed order
                    // (flow -> tracker). If any other code path ever
                    // acquired those same two locks in the OPPOSITE order
                    // (tracker -> flow), that's a classic deadlock - two
                    // threads each holding one lock, waiting for the other's.
                    // We avoid the whole problem by never nesting locks here.
                    flow.sni = hostname;
                    flow.appType = FlowTracker.classifyAppType(hostname);
                    if (rules.shouldBlock(flow)) {
                        flow.blocked = true;
                    }
                }
            }

            pkt.blocked = flow.blocked;
        }
    }
}