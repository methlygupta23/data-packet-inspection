// PcapReader.java
//
// Opens a .pcap file and lets you pull out packets one at a time
// by calling readNextPacket() in a loop.
//
// HOW TO USE THIS CLASS:
//
//   PcapReader reader = new PcapReader("test.pcap");
//   RawPacket pkt;
//   while ((pkt = reader.readNextPacket()) != null) {
//       System.out.println(pkt);
//   }
//   reader.close();

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class PcapReader implements Closeable {

    // This exact number must appear at the start of every valid pcap file.
    private static final int PCAP_MAGIC = 0xa1b2c3d4;

    private final DataInputStream in;
    private ByteOrder byteOrder;   // figured out automatically from the magic number
    private int linkType;          // 1 = Ethernet

    public PcapReader(String filename) throws IOException {
        in = new DataInputStream(new BufferedInputStream(new FileInputStream(filename)));
        readGlobalHeader();
    }

    // ------------------------------------------------------------------
    // Reads the 24-byte header that appears once at the top of the file.
    // ------------------------------------------------------------------
    private void readGlobalHeader() throws IOException {
        byte[] headerBytes = new byte[24];
        in.readFully(headerBytes);  // readFully = "block until you get exactly 24 bytes"

        // Step 1: try reading the first 4 bytes as little-endian and see if
        // it matches the magic number. This is how we detect byte order.
        ByteBuffer buf = ByteBuffer.wrap(headerBytes);
        int magicLittle = buf.order(ByteOrder.LITTLE_ENDIAN).getInt(0);

        if (magicLittle == PCAP_MAGIC) {
            byteOrder = ByteOrder.LITTLE_ENDIAN;
        } else if (Integer.reverseBytes(magicLittle) == PCAP_MAGIC) {
            byteOrder = ByteOrder.BIG_ENDIAN;
        } else {
            throw new IOException(
                "This doesn't look like a valid .pcap file. " +
                "Expected magic number 0xa1b2c3d4 but got 0x" +
                Integer.toHexString(magicLittle));
        }

        // Now that we know the byte order, re-read using the correct order.
        buf.order(byteOrder);
        linkType = buf.getInt(20);  // bytes 20-23 = link type (1 = Ethernet)
    }

    // ------------------------------------------------------------------
    // Reads ONE packet: its 16-byte header, then its raw data.
    // Returns null when there are no more packets (end of file).
    // ------------------------------------------------------------------
    public RawPacket readNextPacket() throws IOException {
        byte[] packetHeaderBytes = new byte[16];

        try {
            in.readFully(packetHeaderBytes);
        } catch (EOFException endOfFile) {
            return null;  // we've read every packet, nothing left
        }

        ByteBuffer header = ByteBuffer.wrap(packetHeaderBytes).order(byteOrder);

        long tsSec    = Integer.toUnsignedLong(header.getInt(0));
        long tsUsec   = Integer.toUnsignedLong(header.getInt(4));
        int capturedLength = header.getInt(8);
        int originalLength = header.getInt(12);

        byte[] data = new byte[capturedLength];
        in.readFully(data);

        return new RawPacket(tsSec, tsUsec, capturedLength, originalLength, data);
    }

    public int getLinkType() {
        return linkType;
    }

    @Override
    public void close() throws IOException {
        in.close();
    }
}