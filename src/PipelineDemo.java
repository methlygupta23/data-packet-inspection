// PipelineDemo.java
//
// STANDALONE TEST for Phase 7. Not part of the real DPI pipeline yet -
// this just proves that LinkedBlockingQueue correctly and safely passes
// Packet objects from one thread (the "producer") to another thread
// (the "consumer") running at the same time.
//
// HOW TO RUN:
//   javac *.java
//   java PipelineDemo

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

public class PipelineDemo {

    // A special "poison pill" packet we send to tell the consumer
    // "there's nothing more coming, you can stop now."
    private static final Packet POISON_PILL = new Packet(null);

    public static void main(String[] args) throws InterruptedException {

        // The queue itself - this is our thread-safe pipe between threads.
        BlockingQueue<Packet> queue = new LinkedBlockingQueue<>();

        // ---- PRODUCER THREAD ----
        // Simulates a "Reader" thread: creates 10 fake packets and pushes
        // them into the queue, one at a time, with a tiny delay to prove
        // the consumer really is processing them as they arrive (not just
        // waiting for everything to be ready first).
        Thread producer = new Thread(() -> {
            for (int i = 1; i <= 10; i++) {
                RawPacket fakeRaw = new RawPacket(1000 + i, 0, 0, 0, new byte[0]);
                Packet pkt = new Packet(fakeRaw);

                try {
                    queue.put(pkt);  // blocks automatically if queue is "full" (it never will be here)
                    System.out.println("[Producer] put packet #" + i + " into queue");
                    Thread.sleep(50); // small delay so we can see interleaving in the output
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }

            // Signal "no more packets coming"
            try {
                queue.put(POISON_PILL);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }

            System.out.println("[Producer] done, sent poison pill");
        }, "Producer-Thread");

        // ---- CONSUMER THREAD ----
        // Simulates a "Worker" thread: pulls packets out of the queue
        // as they become available, and stops when it sees the poison pill.
        Thread consumer = new Thread(() -> {
            int processedCount = 0;

            while (true) {
                Packet pkt;
                try {
                    pkt = queue.take();  // blocks automatically if queue is empty
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                }

                if (pkt == POISON_PILL) {
                    System.out.println("[Consumer] received poison pill, stopping");
                    break;
                }

                processedCount++;
                System.out.println("[Consumer] processed packet with timestamp "
                        + pkt.raw.tsSec);
            }

            System.out.println("[Consumer] total packets processed: " + processedCount);
        }, "Consumer-Thread");

        // Start both threads - they now run CONCURRENTLY, not one after another
        producer.start();
        consumer.start();

        // Wait for both to finish before the program exits
        producer.join();
        consumer.join();

        System.out.println("Pipeline demo complete - queue worked correctly across threads.");
    }
}