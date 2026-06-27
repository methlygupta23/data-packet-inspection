// WriterThread.java
//
// Runs as its own thread. Pulls fully-processed Packet objects off the
// output queue, writes the ones that aren't blocked to the output file,
// and keeps running totals using AtomicLong (thread-safe counters).
//
// In Phase 8 there's only ONE writer, so AtomicLong isn't strictly
// necessary yet - but we use it anyway because Phase 9's design may
// introduce multiple writer/output paths, and it costs nothing now.

import java.io.IOException;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.atomic.AtomicLong;

public class WriterThread extends Thread {

    private final String outputFile;
    private final BlockingQueue<Packet> inputQueue;
    private final int numWorkers; // how many poison pills to expect before stopping

    // Thread-safe counters - safe to read from the main thread after join()
    public final AtomicLong totalPackets = new AtomicLong(0);
    public final AtomicLong forwardedPackets = new AtomicLong(0);
    public final AtomicLong droppedPackets = new AtomicLong(0);

    public WriterThread(String outputFile, BlockingQueue<Packet> inputQueue, int numWorkers) {
        super("Writer-Thread");
        this.outputFile = outputFile;
        this.inputQueue = inputQueue;
        this.numWorkers = numWorkers;
    }

    @Override
    public void run() {
        int poisonPillsSeen = 0;

        try (PcapWriter writer = new PcapWriter(outputFile)) {

            while (poisonPillsSeen < numWorkers) {
                Packet pkt;
                try {
                    pkt = inputQueue.take();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                }

                if (pkt instanceof PoisonPill) {
                    poisonPillsSeen++; // wait until ALL workers have signaled done
                    continue;
                }

                totalPackets.incrementAndGet();

                if (pkt.blocked) {
                    droppedPackets.incrementAndGet();
                } else {
                    forwardedPackets.incrementAndGet();
                    writer.writePacket(pkt.raw);
                }
            }

        } catch (IOException e) {
            System.out.println("[Writer] Error writing output file: " + e.getMessage());
        }

        System.out.println("[Writer] finished - wrote " + forwardedPackets.get() + " packets to " + outputFile);
    }
}