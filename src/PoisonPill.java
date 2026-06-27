// PoisonPill.java
//
// A special marker object we push into a queue to tell a consuming
// thread "there's nothing more coming - stop now."
//
// Why a separate class instead of just using `null`?
// BlockingQueue does NOT allow null elements at all (it throws an
// exception if you try) - so we need a real, distinct object instead.
//
// We extend Packet so it can travel through the same queues as real
// Packet objects without needing a different queue type.

public class PoisonPill extends Packet {

    // Only one instance ever needed - all threads check for this exact object.
    public static final PoisonPill INSTANCE = new PoisonPill();

    private PoisonPill() {
        super(null);
    }
}