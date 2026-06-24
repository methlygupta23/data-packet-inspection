// RawPacket.java
//
// This class holds ONE packet exactly as it came out of the .pcap file —
// before we understand anything about Ethernet, IP, or TCP.
//
// Think of it like an unopened envelope: we know when it arrived (timestamp)
// and how big it is, but we haven't read what's inside yet.

public class RawPacket {

    public final long   tsSec;     // timestamp - seconds part
    public final long   tsUsec;    // timestamp - microseconds part (fine detail)
    public final int    capturedLength;  // how many bytes we actually saved
    public final int    originalLength; // how big the packet was on the real network
    public final byte[] data;      // the actual raw bytes of the packet

    public RawPacket(long tsSec, long tsUsec, int capturedLength, int originalLength, byte[] data) {
        this.tsSec          = tsSec;
        this.tsUsec         = tsUsec;
        this.capturedLength = capturedLength;
        this.originalLength = originalLength;
        this.data           = data;
    }

    @Override
    public String toString() {
        return String.format("Packet @ %d.%06d sec | captured=%d bytes | original=%d bytes",
                tsSec, tsUsec, capturedLength, originalLength);
    }
}