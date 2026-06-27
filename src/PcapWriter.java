// PcapWriter.java
//
// Writes packets to a NEW .pcap file, in the exact same binary format
// that PcapReader knows how to read. This lets us produce an output
// file containing only the "allowed" (non-blocked) packets - openable
// in Wireshark just like any normal capture.
//
// HOW TO USE:
//   PcapWriter writer = new PcapWriter("output.pcap");
//   writer.writePacket(rawPacket);   // call once per packet you want to keep
//   writer.close();

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class PcapWriter implements Closeable {

    private final DataOutputStream out;

    public PcapWriter(String filename) throws IOException {
        out = new DataOutputStream(new BufferedOutputStream(new FileOutputStream(filename)));
        writeGlobalHeader();
    }

    // Writes the 24-byte global header that must appear once at the
    // very top of the file. We always write little-endian, since that's
    // the most common format (and what our test files use).
    private void writeGlobalHeader() throws IOException {
        ByteBuffer buf = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN);
        buf.putInt(0xa1b2c3d4);  // magic number
        buf.putShort((short) 2); // version major
        buf.putShort((short) 4); // version minor
        buf.putInt(0);           // timezone (unused)
        buf.putInt(0);           // sigfigs (unused)
        buf.putInt(65535);       // snaplen (max bytes per packet)
        buf.putInt(1);           // link type = 1 (Ethernet)
        out.write(buf.array());
    }

    // Writes one packet: its 16-byte header, then its raw data bytes.
    // Takes a RawPacket because that's where the original timestamp
    // and byte data already live - no need to re-encode anything.
    public void writePacket(RawPacket pkt) throws IOException {
        ByteBuffer header = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
        header.putInt((int) pkt.tsSec);
        header.putInt((int) pkt.tsUsec);
        header.putInt(pkt.capturedLength);
        header.putInt(pkt.originalLength);
        out.write(header.array());
        out.write(pkt.data, 0, pkt.capturedLength);
    }

    @Override
    public void close() throws IOException {
        out.flush();
        out.close();
    }
}