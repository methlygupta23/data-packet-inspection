// ReaderThread.java
//
// Runs as its own thread. Its ONLY job: open the input .pcap file,
// read every packet, and push each one into a single queue for the
// LoadBalancerThread to pick up.
//
// NOTE (Phase 9 change): this used to ALSO hash packets and route them
// directly to worker queues (Phase 8). We've now split that hashing
// responsibility out into its own LoadBalancerThread, so this class
// goes back to doing just ONE job: reading bytes from disk as fast as
// possible. This means slow disk I/O and CPU-bound hashing no longer
// compete for the same thread's time.

import java.io.IOException;
import java.util.concurrent.BlockingQueue;

public class ReaderThread extends Thread {

    private final String inputFile;
    private final BlockingQueue<Packet> outputQueue;

    public ReaderThread(String inputFile, BlockingQueue<Packet> outputQueue) {
        super("Reader-Thread");
        this.inputFile = inputFile;
        this.outputQueue = outputQueue;
    }

    @Override
    public void run() {
        int count = 0;
        try (PcapReader reader = new PcapReader(inputFile)) {

            RawPacket raw;
            while ((raw = reader.readNextPacket()) != null) {
                outputQueue.put(new Packet(raw)); // blocks if queue is full
                count++;
            }

        } catch (IOException e) {
            System.out.println("[Reader] Error reading file: " + e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        // Only ONE poison pill needed now - there's only ONE LoadBalancerThread
        // consuming this queue (unlike Phase 8, where every worker needed one).
        try {
            outputQueue.put(PoisonPill.INSTANCE);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        System.out.println("[Reader] finished - read " + count + " packets total");
    }
}