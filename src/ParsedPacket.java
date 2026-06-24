// ParsedPacket.java
//
// Once we peel apart the Ethernet/IP/TCP layers, the results go here.
// This is the "useful" version of a packet - instead of raw bytes,
// we now have real numbers: IP addresses, ports, protocol type.

public class ParsedPacket {

    // ---- Ethernet layer ----
    public int etherType;     // 0x0800 = IPv4. We only handle IPv4 in this project.

    // ---- IP layer ----
    public int srcIp;         // stored as a 32-bit int (4 bytes packed together)
    public int dstIp;
    public int ipProtocol;    // 6 = TCP, 17 = UDP
    public int ipHeaderLength; // actual byte length of the IP header (usually 20)

    // ---- TCP / UDP layer ----
    public int srcPort;
    public int dstPort;
    public boolean isTcp;
    public boolean isUdp;

    // ---- Payload (whatever comes after all headers - TLS, HTTP, etc.) ----
    public byte[] payload;

    // Keep a reference to the original raw packet too -
    // we'll need it later when writing allowed packets to an output file.
    public RawPacket raw;

    // Helper: convert the 32-bit srcIp/dstIp into a readable "192.168.1.5" string
    public static String ipToString(int ip) {
        return ((ip >> 24) & 0xFF) + "."
             + ((ip >> 16) & 0xFF) + "."
             + ((ip >>  8) & 0xFF) + "."
             + ( ip        & 0xFF);
    }

    @Override
    public String toString() {
        String proto = isTcp ? "TCP" : isUdp ? "UDP" : "OTHER(" + ipProtocol + ")";
        return String.format("%s  %s:%d -> %s:%d  payload=%d bytes",
                proto,
                ipToString(srcIp), srcPort,
                ipToString(dstIp), dstPort,
                payload == null ? 0 : payload.length);
    }
}