// SniExtractor.java
//
// Looks inside a TCP payload (the bytes after the TCP header) to see if
// it's a TLS "Client Hello" message, and if so, pulls out the SNI
// (Server Name Indication) - the plain-text domain name like "youtube.com"
// that gets sent BEFORE encryption starts.
//
// HOW TO USE:
//   String hostname = SniExtractor.extract(parsedPacket.payload);
//   if (hostname != null) {
//       System.out.println("Found domain: " + hostname);
//   }
//
// Returns null if this isn't a TLS Client Hello, or if anything looks malformed.
// We never throw exceptions here on purpose - malformed/truncated packets
// are common and should just be skipped, not crash the program.

public class SniExtractor {

    public static String extract(byte[] payload) {
        if (payload == null || payload.length < 6) {
            return null; // too short to even check
        }

        try {
            return tryExtract(payload);
        } catch (Exception e) {
            // Any unexpected indexing issue just means "not a valid Client Hello"
            // We silently skip rather than crash - malformed packets are normal.
            return null;
        }
    }

    private static String tryExtract(byte[] data) {
        int pos = 0;

        // ---- TLS Record Header (5 bytes) ----
        int recordType = data[pos] & 0xFF;
        if (recordType != 0x16) {
            return null; // not a TLS Handshake record at all
        }
        pos += 5; // skip: record type(1) + version(2) + length(2)

        // ---- Handshake Header ----
        if (pos >= data.length) return null;
        int handshakeType = data[pos] & 0xFF;
        if (handshakeType != 0x01) {
            return null; // not a Client Hello (could be Server Hello, etc.)
        }
        pos += 4; // skip: handshake type(1) + handshake length(3)

        // ---- Client Hello body ----
        pos += 2;  // skip client version (2 bytes)
        pos += 32; // skip random (32 bytes)

        // Session ID: length-prefixed (1 byte length + that many bytes)
        if (pos >= data.length) return null;
        int sessionIdLen = data[pos] & 0xFF;
        pos += 1 + sessionIdLen;

        // Cipher Suites: length-prefixed (2 byte length + that many bytes)
        if (pos + 2 > data.length) return null;
        int cipherSuitesLen = readUint16(data, pos);
        pos += 2 + cipherSuitesLen;

        // Compression Methods: length-prefixed (1 byte length + that many bytes)
        if (pos >= data.length) return null;
        int compressionMethodsLen = data[pos] & 0xFF;
        pos += 1 + compressionMethodsLen;

        // Extensions: length-prefixed (2 byte length), then a list of extensions
        if (pos + 2 > data.length) return null;
        int extensionsLen = readUint16(data, pos);
        pos += 2;

        int extensionsEnd = pos + extensionsLen;
        if (extensionsEnd > data.length) {
            extensionsEnd = data.length; // be lenient - truncated capture
        }

        // ---- Walk through each extension looking for type 0x0000 (Server Name) ----
        while (pos + 4 <= extensionsEnd) {
            int extType = readUint16(data, pos);
            int extLen  = readUint16(data, pos + 2);
            int extDataStart = pos + 4;

            if (extType == 0x0000) {
                // Found the Server Name extension! Parse it.
                return parseServerNameExtension(data, extDataStart, extLen);
            }

            pos = extDataStart + extLen; // move to the next extension
        }

        return null; // no Server Name extension found
    }

    // ---- Server Name Indication extension structure ----
    // Bytes 0-1: Server Name List Length
    // Byte 2:    Name Type (0x00 = hostname, the only type that exists in practice)
    // Bytes 3-4: Hostname Length
    // [Hostname bytes as plain ASCII text]
    private static String parseServerNameExtension(byte[] data, int start, int extLen) {
        if (start + 5 > data.length) return null;

        int nameType = data[start + 2] & 0xFF;
        if (nameType != 0x00) return null; // not a hostname entry

        int hostnameLen = readUint16(data, start + 3);
        int hostnameStart = start + 5;

        if (hostnameStart + hostnameLen > data.length) return null;

        return new String(data, hostnameStart, hostnameLen,
                java.nio.charset.StandardCharsets.US_ASCII);
    }

    // Reads 2 bytes as one unsigned 16-bit number (big-endian, network order)
    private static int readUint16(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    }
}