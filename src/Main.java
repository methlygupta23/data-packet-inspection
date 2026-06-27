// Main.java
//
// PHASE 6 VERSION.
// Adds: writing forwarded (non-blocked) packets to an output .pcap file,
// and a clean final summary report using ReportGenerator.

import java.io.IOException;

public class Main {
    public static void main(String[] args) {

        if (args.length < 1) {
            System.out.println("Usage: java Main <input-pcap-file> [output-pcap-file]");
            return;
        }

        String inputFile  = args[0];
        String outputFile = args.length > 1 ? args[1] : "output.pcap";

        int totalPackets = 0;
        int parsedPackets = 0;
        int forwardedPackets = 0;
        int droppedPackets = 0;

        FlowTracker tracker = new FlowTracker();

        RuleManager rules = new RuleManager();
        rules.blockApp(AppType.YOUTUBE);
        rules.blockDomainContaining("facebook");
        // rules.blockIp("8.8.8.8");

        try (PcapReader reader = new PcapReader(inputFile);
             PcapWriter writer = new PcapWriter(outputFile)) {

            System.out.println("Reading from: " + inputFile);
            System.out.println("Writing allowed packets to: " + outputFile);
            System.out.println("Blocking: YOUTUBE app, domains containing 'facebook'");
            System.out.println("----------------------------------------");

            RawPacket raw;
            while ((raw = reader.readNextPacket()) != null) {
                totalPackets++;

                ParsedPacket parsed = PacketParser.parse(raw);
                if (parsed == null) {
                    // Couldn't parse it (not IPv4 TCP/UDP) - just forward it as-is,
                    // we have no basis to block traffic we can't even identify.
                    writer.writePacket(raw);
                    forwardedPackets++;
                    continue;
                }
                parsedPackets++;

                FiveTuple key = new FiveTuple(
                        Integer.toUnsignedLong(parsed.srcIp),
                        Integer.toUnsignedLong(parsed.dstIp),
                        parsed.srcPort,
                        parsed.dstPort,
                        parsed.isTcp ? 6 : 17);

                Flow flow = tracker.getOrCreateFlow(key);
                flow.packetCount++;

                if (flow.sni == null && parsed.isTcp && parsed.dstPort == 443) {
                    String hostname = SniExtractor.extract(parsed.payload);
                    if (hostname != null) {
                        tracker.recordSni(flow, hostname);
                        if (rules.shouldBlock(flow)) {
                            flow.blocked = true;
                        }
                    }
                }

                if (flow.blocked) {
                    droppedPackets++;
                    // Not written to output - this is the actual "blocking" action
                } else {
                    forwardedPackets++;
                    writer.writePacket(raw);
                }
            }

            ReportGenerator.printReport(totalPackets, forwardedPackets, droppedPackets, tracker);

        } catch (IOException e) {
            System.out.println("Error processing pcap file: " + e.getMessage());
        }
    }
}