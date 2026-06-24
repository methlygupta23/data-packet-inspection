// PacketParser.java
//
// Takes a RawPacket (just bytes) and turns it into a ParsedPacket
// (real IP addresses, ports, protocol) by reading through the
// Ethernet -> IP -> TCP/UDP layers in order.
//
// HOW TO USE:
//   ParsedPacket parsed = PacketParser.parse(rawPacket);
//   if (parsed != null) {
//       System.out.println(parsed);
//   }
//
// Returns null if the packet isn't IPv4, or is too short to be valid -
// we simply skip those packets rather than crash.

public class PacketParser {

    private static final int ETHERNET_HEADER_LEN = 14;
    private static final int ETHERTYPE_IPV4 = 0x0800;

    public static ParsedPacket parse(RawPacket raw) {
        byte[] data = raw.data;

        // Sanity check: not even enough bytes for an Ethernet header? Skip it.
        if (data.length < ETHERNET_HEADER_LEN) {
            return null;
        }

        ParsedPacket p = new ParsedPacket();
        p.raw = raw;

        // ------------------------------------------------------------
        // LAYER 1: ETHERNET (14 bytes)
        // Bytes 0-5 = dest MAC, 6-11 = src MAC, 12-13 = EtherType
        // We only care about EtherType here.
        // ------------------------------------------------------------
        int etherType = ((data[12] & 0xFF) << 8) | (data[13] & 0xFF);
        p.etherType = etherType;

        if (etherType != ETHERTYPE_IPV4) {
            return null; // not IPv4 (could be IPv6, ARP, etc.) - skip for this project
        }

        int ipStart = ETHERNET_HEADER_LEN; // IP header begins right after Ethernet

        if (data.length < ipStart + 20) {
            return null; // not enough bytes for even a minimal IP header
        }

        // ------------------------------------------------------------
        // LAYER 2: IP HEADER (20 bytes minimum, can be longer)
        // ------------------------------------------------------------

        // Byte 0: top 4 bits = version, bottom 4 bits = header length (in 4-byte words)
        int versionAndHeaderLen = data[ipStart] & 0xFF;
        int ipHeaderLength = (versionAndHeaderLen & 0x0F) * 4; // convert words -> bytes

        if (ipHeaderLength < 20) {
            return null; // malformed - shouldn't ever be smaller than 20
        }

        // Byte 9: protocol number (6 = TCP, 17 = UDP)
        int protocol = data[ipStart + 9] & 0xFF;
        p.ipProtocol = protocol;
        p.ipHeaderLength = ipHeaderLength;

        // Bytes 12-15: source IP (4 bytes, big-endian, packed into one int)
        p.srcIp = bytesToInt(data, ipStart + 12);
        // Bytes 16-19: destination IP
        p.dstIp = bytesToInt(data, ipStart + 16);

        int afterIp = ipStart + ipHeaderLength; // where TCP/UDP header begins

        // ------------------------------------------------------------
        // LAYER 3: TCP or UDP HEADER
        // ------------------------------------------------------------
        if (protocol == 6) {
            // ---- TCP ----
            if (data.length < afterIp + 20) return null; // too short for TCP header

            p.isTcp = true;
            p.srcPort = ((data[afterIp] & 0xFF) << 8) | (data[afterIp + 1] & 0xFF);
            p.dstPort = ((data[afterIp + 2] & 0xFF) << 8) | (data[afterIp + 3] & 0xFF);

            // Byte 12 of TCP header: top 4 bits = header length (in 4-byte words)
            int tcpHeaderLength = ((data[afterIp + 12] & 0xFF) >> 4) * 4;
            if (tcpHeaderLength < 20) return null;

            int payloadStart = afterIp + tcpHeaderLength;
            p.payload = slice(data, payloadStart);

        } else if (protocol == 17) {
            // ---- UDP ---- (fixed 8-byte header, much simpler than TCP)
            if (data.length < afterIp + 8) return null;

            p.isUdp = true;
            p.srcPort = ((data[afterIp] & 0xFF) << 8) | (data[afterIp + 1] & 0xFF);
            p.dstPort = ((data[afterIp + 2] & 0xFF) << 8) | (data[afterIp + 3] & 0xFF);

            int payloadStart = afterIp + 8; // UDP header is always exactly 8 bytes
            p.payload = slice(data, payloadStart);

        } else {
            // Not TCP or UDP (e.g. ICMP) - we don't analyze these in this project
            return null;
        }

        return p;
    }

    // Reads 4 bytes starting at `offset` and packs them into one 32-bit int.
    // Used for IP addresses, which are naturally 4 bytes (e.g. 192.168.1.5).
    private static int bytesToInt(byte[] data, int offset) {
        return ((data[offset]     & 0xFF) << 24)
             | ((data[offset + 1] & 0xFF) << 16)
             | ((data[offset + 2] & 0xFF) << 8)
             |  (data[offset + 3] & 0xFF);
    }

    // Returns everything in `data` from `start` to the end, as a new array.
    // If start is past the end of the array, returns an empty array (not an error).
    private static byte[] slice(byte[] data, int start) {
        if (start >= data.length) {
            return new byte[0];
        }
        byte[] result = new byte[data.length - start];
        System.arraycopy(data, start, result, 0, result.length);
        return result;
    }
}