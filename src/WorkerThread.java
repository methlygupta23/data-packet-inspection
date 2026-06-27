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
        flow.packetCount++;

        if (flow.sni == null && parsed.isTcp && parsed.dstPort == 443) {
            String hostname = SniExtractor.extract(parsed.payload);
            if (hostname != null) {
                tracker.recordSni(flow, hostname); // thread-safe (synchronized inside)
                if (rules.shouldBlock(flow)) {
                    flow.blocked = true;
                }
            }
        }

        pkt.blocked = flow.blocked;
    }
}