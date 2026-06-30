// LoadBalancerThread.java
//
// Runs as its own thread, between the Reader and the Workers. Its ONLY
// job: pull raw packets off the Reader's queue, compute a hash of each
// packet's five-tuple (using QuickFlowHash), and push it into the
// correct WORKER's queue based on that hash.
//
// WHY THIS EXISTS AS ITS OWN THREAD (separate from the Reader):
// In Phase 8, the Reader thread did both reading AND hashing. That
// works, but means disk I/O (slow, waiting on hardware) and hashing
// (fast, pure CPU work) compete for the same thread's time. Splitting
// them into separate threads lets disk reads continue piling up packets
// into the queue WHILE the load balancer is busy hashing earlier ones -
// genuine parallelism between two different KINDS of work.
//
// WHY HASHING MATTERS FOR CORRECTNESS (not just performance):
// Every packet belonging to the same five-tuple (same connection) MUST
// always be routed to the same worker queue. Otherwise, two packets
// from one connection could be processed by different workers at the
// same time, in the wrong order - which caused a real race condition
// during Phase 8 testing (blocking decisions read before they were set).

import java.util.concurrent.BlockingQueue;

public class LoadBalancerThread extends Thread {

    private final BlockingQueue<Packet> inputQueue;          // from the Reader
    private final BlockingQueue<Packet>[] workerQueues;      // one per worker

    public LoadBalancerThread(BlockingQueue<Packet> inputQueue,
                               BlockingQueue<Packet>[] workerQueues) {
        super("LoadBalancer-Thread");
        this.inputQueue = inputQueue;
        this.workerQueues = workerQueues;
    }

    @Override
    public void run() {
        int routedCount = 0;

        while (true) {
            Packet pkt;
            try {
                pkt = inputQueue.take();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }

            if (pkt instanceof PoisonPill) {
                break; // Reader is done - no more packets coming
            }

            int workerIndex = chooseWorker(pkt.raw);
            try {
                workerQueues[workerIndex].put(pkt);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
            routedCount++;
        }

        // Forward a poison pill to EVERY worker now that routing is done.
        try {
            for (BlockingQueue<Packet> queue : workerQueues) {
                queue.put(PoisonPill.INSTANCE);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        System.out.println("[LoadBalancer] finished - routed " + routedCount + " packets across "
                + workerQueues.length + " workers");
    }

    private int chooseWorker(RawPacket raw) {
        int hash = QuickFlowHash.hash(raw);
        return Math.floorMod(hash, workerQueues.length);
    }
}