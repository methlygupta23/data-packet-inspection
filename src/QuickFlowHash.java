// QuickFlowHash.java
//
// Computes a hash of a packet's five-tuple DIRECTLY from raw bytes,
// without doing the full PacketParser.parse(). We need this hash before
// full parsing happens, because the ReaderThread must decide which
// worker queue to send the packet to - and full parsing happens later,
// inside whichever worker receives it.
//
// This duplicates a small amount of byte-reading logic from PacketParser,
// but only the minimum needed to get src/dst IP and ports.

public class QuickFlowHash {

    public static int hash(RawPacket raw) {
        byte[] data = raw.data;

        // Same offsets as PacketParser - see that class for full explanation.
        if (data.length < 14 + 20) {
            return 0; // too short to have a five-tuple - just lump it in worker 0
        }

        int etherType = ((data[12] & 0xFF) << 8) | (data[13] & 0xFF);
        if (etherType != 0x0800) {
            return 0; // not IPv4 - doesn't matter which worker handles it
        }

        int ipStart = 14;
        int versionAndHeaderLen = data[ipStart] & 0xFF;
        int ipHeaderLength = (versionAndHeaderLen & 0x0F) * 4;

        if (ipHeaderLength < 20 || data.length < ipStart + ipHeaderLength + 4) {
            return 0;
        }

        int srcIp = bytesToInt(data, ipStart + 12);
        int dstIp = bytesToInt(data, ipStart + 16);

        int afterIp = ipStart + ipHeaderLength;
        int srcPort = 0, dstPort = 0;
        if (data.length >= afterIp + 4) {
            srcPort = ((data[afterIp] & 0xFF) << 8) | (data[afterIp + 1] & 0xFF);
            dstPort = ((data[afterIp + 2] & 0xFF) << 8) | (data[afterIp + 3] & 0xFF);
        }

        // Combine everything into one hash - doesn't need to match
        // FiveTuple.hashCode() exactly, just needs to be CONSISTENT for
        // the same connection every time.
        int hash = srcIp;
        hash = hash * 31 + dstIp;
        hash = hash * 31 + srcPort;
        hash = hash * 31 + dstPort;
        return hash;
    }

    private static int bytesToInt(byte[] data, int offset) {
        return ((data[offset]     & 0xFF) << 24)
             | ((data[offset + 1] & 0xFF) << 16)
             | ((data[offset + 2] & 0xFF) << 8)
             |  (data[offset + 3] & 0xFF);
    }
}