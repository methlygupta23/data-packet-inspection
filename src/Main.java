// Main.java
//
// PHASE 2 TEST VERSION.
// Reads a .pcap file, parses each packet's Ethernet/IP/TCP headers,
// and prints the source/destination IP:port for each one.

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

        try (PcapReader reader = new PcapReader(filename)) {

            System.out.println("Opened file: " + filename);
            System.out.println("Link type: " + reader.getLinkType() + " (1 = Ethernet)");
            System.out.println("----------------------------------------");

            RawPacket raw;
            while ((raw = reader.readNextPacket()) != null) {
                totalPackets++;

                ParsedPacket parsed = PacketParser.parse(raw);
                if (parsed == null) {
                    System.out.println("Packet #" + totalPackets + ": skipped (not IPv4 TCP/UDP)");
                    continue;
                }

                parsedPackets++;
                System.out.println("Packet #" + totalPackets + ": " + parsed);
            }

            System.out.println("----------------------------------------");
            System.out.println("Total packets read: " + totalPackets);
            System.out.println("Successfully parsed: " + parsedPackets);

        } catch (IOException e) {
            System.out.println("Error reading pcap file: " + e.getMessage());
        }
    }
}