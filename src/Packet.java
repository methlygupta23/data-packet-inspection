// Packet.java
//
// This is the object that travels THROUGH the queue between threads.
// Right now it just wraps a RawPacket, but as we build out the pipeline
// (Phase 8+), worker threads will fill in the `parsed` field too -
// so later stages (rules, writer) don't need to re-parse anything.
//
// Think of this like a tray in a cafeteria line - it starts with just
// raw ingredients (RawPacket), and gets more added to it (ParsedPacket,
// Flow info) as it moves down the line through different stations.

public class Packet {

    public final RawPacket raw;     // always present - the original bytes
    public ParsedPacket    parsed;  // filled in by a worker thread later
    public boolean         blocked; // filled in once rules have been checked

    public Packet(RawPacket raw) {
        this.raw = raw;
        this.parsed = null;
        this.blocked = false;
    }
}