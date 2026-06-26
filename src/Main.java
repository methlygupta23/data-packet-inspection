// Main.java
//
// PHASE 4 TEST VERSION.
// Now uses FlowTracker to "remember" SNI/app-type per connection,
// so every packet on a flow gets tagged correctly - not just the
// first packet where SNI was actually found.

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

        FlowTracker tracker = new FlowTracker();

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

                // Build the five-tuple "fingerprint" for this packet's connection
                FiveTuple key = new FiveTuple(
                        Integer.toUnsignedLong(parsed.srcIp),
                        Integer.toUnsignedLong(parsed.dstIp),
                        parsed.srcPort,
                        parsed.dstPort,
                        parsed.isTcp ? 6 : 17);

                // Look up (or create) the Flow for this connection
                Flow flow = tracker.getOrCreateFlow(key);
                flow.packetCount++;

                // Only try extracting SNI if we don't already know it for this flow -
                // saves work, and avoids re-parsing payloads that won't have SNI anyway
                // (SNI only appears once, in the Client Hello).
                if (flow.sni == null && parsed.isTcp && parsed.dstPort == 443) {
                    String hostname = SniExtractor.extract(parsed.payload);
                    if (hostname != null) {
                        tracker.recordSni(flow, hostname);
                    }
                }

                String line = "Packet #" + totalPackets + ": " + parsed;
                if (flow.sni != null) {
                    line += "  [flow: " + flow.sni + " / " + flow.appType + "]";
                }
                System.out.println(line);
            }

            System.out.println("----------------------------------------");
            System.out.println("Total packets read: " + totalPackets);
            System.out.println("Successfully parsed: " + parsedPackets);
            System.out.println("Distinct flows tracked: " + tracker.getFlowCount());

            System.out.println("----------------------------------------");
            System.out.println("Flow summary:");
            for (Flow f : tracker.getAllFlows().values()) {
                System.out.println("  " + f);
            }

        } catch (IOException e) {
            System.out.println("Error reading pcap file: " + e.getMessage());
        }
    }
}