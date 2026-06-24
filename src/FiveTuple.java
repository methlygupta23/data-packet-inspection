// FiveTuple.java
// Every TCP connection is uniquely identified by these 5 values.
// Two packets with the same 5 values belong to the same conversation.
//
// Example:
//   srcIp=192.168.1.5  srcPort=54321
//   dstIp=142.250.1.1  dstPort=443
//   protocol=6 (TCP)
//
// Why store IPs as long instead of String?
//   "192.168.1.5" takes 11 chars of memory and is slow to compare.
//   Stored as a 32-bit number it's just one integer comparison.

import java.util.Objects;

public class FiveTuple {

    public final long srcIp;      // 32-bit IP stored in a long (avoids sign issues)
    public final long dstIp;
    public final int  srcPort;    // 0-65535
    public final int  dstPort;
    public final int  protocol;   // 6=TCP, 17=UDP

    public FiveTuple(long srcIp, long dstIp,
                     int srcPort, int dstPort, int protocol) {
        this.srcIp    = srcIp;
        this.dstIp    = dstIp;
        this.srcPort  = srcPort;
        this.dstPort  = dstPort;
        this.protocol = protocol;
    }

    // Java needs this to compare two FiveTuple objects for equality.
    // Without it, HashMap can't find existing entries.
    @Override
    public boolean equals(Object o) {
        if (!(o instanceof FiveTuple)) return false;
        FiveTuple t = (FiveTuple) o;
        return srcIp == t.srcIp && dstIp == t.dstIp
            && srcPort == t.srcPort && dstPort == t.dstPort
            && protocol == t.protocol;
    }

    // Java needs this to put FiveTuple into a HashMap.
    // Two equal FiveTuples MUST return the same hash code.
    @Override
    public int hashCode() {
        return Objects.hash(srcIp, dstIp, srcPort, dstPort, protocol);
    }

    // Helper: convert a 32-bit IP number back to "192.168.1.5" for printing
    public static String ipToString(long ip) {
        return ((ip >> 24) & 0xFF) + "."
             + ((ip >> 16) & 0xFF) + "."
             + ((ip >>  8) & 0xFF) + "."
             + ( ip        & 0xFF);
    }

    @Override
    public String toString() {
        return ipToString(srcIp) + ":" + srcPort
             + " → " + ipToString(dstIp) + ":" + dstPort
             + " (proto=" + protocol + ")";
    }
}