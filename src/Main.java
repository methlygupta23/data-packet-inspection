// Main.java
//
// PHASE 3 TEST VERSION.
// Reads a .pcap file, parses Ethernet/IP/TCP headers, and for any
// TCP traffic on port 443, tries to extract the SNI (domain name)
// from the TLS Client Hello.

import java.io.IOException;

public class Main {
    public static void main(String[] args) {

        if (args.length < 1) {
            System.out.println("Usage: java Main <path-to-pcap-file>");
            return;
        }

        String filename = args[0];
        int totalPackets = 0;
        int parsedPackets = 0;
        int sniFound = 0;

        try (PcapReader reader = new PcapReader(filename)) {

            System.out.println("Opened file: " + filename);
            System.out.println("----------------------------------------");

            RawPacket raw;
            while ((raw = reader.readNextPacket()) != null) {
                totalPackets++;

                ParsedPacket parsed = PacketParser.parse(raw);
                if (parsed == null) {
                    continue;
                }
                parsedPackets++;

                String line = "Packet #" + totalPackets + ": " + parsed;

                // Only bother checking for SNI on traffic headed to port 443 (HTTPS)
                if (parsed.isTcp && parsed.dstPort == 443) {
                    String hostname = SniExtractor.extract(parsed.payload);
                    if (hostname != null) {
                        sniFound++;
                        line += "  >>> SNI found: " + hostname;
                    }
                }

                System.out.println(line);
            }

            System.out.println("----------------------------------------");
            System.out.println("Total packets read: " + totalPackets);
            System.out.println("Successfully parsed: " + parsedPackets);
            System.out.println("SNI domains found: " + sniFound);

        } catch (IOException e) {
            System.out.println("Error reading pcap file: " + e.getMessage());
        }
    }
}