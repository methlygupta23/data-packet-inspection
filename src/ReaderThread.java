// ReaderThread.java
//
// Runs as its own thread. Its ONLY job: open the input .pcap file,
// read every packet, and push each one (wrapped as a Packet) into
// the input queue for worker threads to pick up.
//
// Reading from disk is inherently sequential (we can't read a single
// file in parallel), so this stays as ONE thread - but it can run
// WHILE worker threads are simultaneously processing earlier packets,
// which is the whole point of splitting this into a pipeline.

import java.io.IOException;
import java.util.concurrent.BlockingQueue;

public class ReaderThread extends Thread {

    private final String inputFile;
    private final BlockingQueue<Packet> outputQueue;
    private final int numWorkers; // how many poison pills to send when done

    public ReaderThread(String inputFile, BlockingQueue<Packet> outputQueue, int numWorkers) {
        super("Reader-Thread");
        this.inputFile = inputFile;
        this.outputQueue = outputQueue;
        this.numWorkers = numWorkers;
    }

    @Override
    public void run() {
        int count = 0;
        try (PcapReader reader = new PcapReader(inputFile)) {

            RawPacket raw;
            while ((raw = reader.readNextPacket()) != null) {
                Packet pkt = new Packet(raw);
                outputQueue.put(pkt); // blocks if queue is full - applies natural backpressure
                count++;
            }

        } catch (IOException e) {
            System.out.println("[Reader] Error reading file: " + e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        // Send one poison pill PER WORKER, so every worker thread knows to stop.
        // (If we only sent one, only one worker would see it and stop - the
        // others would wait forever on queue.take().)
        try {
            for (int i = 0; i < numWorkers; i++) {
                outputQueue.put(PoisonPill.INSTANCE);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        System.out.println("[Reader] finished - read " + count + " packets total");
    }
}