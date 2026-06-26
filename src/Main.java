// Main.java
//
// PHASE 5 TEST VERSION.
// Adds RuleManager: once a flow's SNI/app is known, we check if it
// should be blocked. Blocked flows have every packet dropped -
// including encrypted ones with no visible SNI, because we remember
// the decision on the Flow object itself.

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
        int forwardedPackets = 0;
        int droppedPackets = 0;

        FlowTracker tracker = new FlowTracker();

        // ---- Set up blocking rules here ----
        RuleManager rules = new RuleManager();
        rules.blockApp(AppType.YOUTUBE);          // block by app type
        rules.blockDomainContaining("facebook");  // block by domain keyword
        // rules.blockIp("8.8.8.8");               // example: block by IP (uncomment to use)

        try (PcapReader reader = new PcapReader(filename)) {

            System.out.println("Opened file: " + filename);
            System.out.println("Blocking: YOUTUBE app, domains containing 'facebook'");
            System.out.println("----------------------------------------");

            RawPacket raw;
            while ((raw = reader.readNextPacket()) != null) {
                totalPackets++;

                ParsedPacket parsed = PacketParser.parse(raw);
                if (parsed == null) {
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

                // Only extract SNI if we don't already know it for this flow
                if (flow.sni == null && parsed.isTcp && parsed.dstPort == 443) {
                    String hostname = SniExtractor.extract(parsed.payload);
                    if (hostname != null) {
                        tracker.recordSni(flow, hostname);

                        // The moment we learn the SNI, check the rules ONCE.
                        // This decision then applies to every future packet on this flow.
                        if (rules.shouldBlock(flow)) {
                            flow.blocked = true;
                        }
                    }
                }

                String status = flow.blocked ? "DROPPED" : "forwarded";
                if (flow.blocked) {
                    droppedPackets++;
                } else {
                    forwardedPackets++;
                }

                String line = "Packet #" + totalPackets + ": " + parsed + "  [" + status + "]";
                if (flow.sni != null) {
                    line += "  (" + flow.sni + " / " + flow.appType + ")";
                }
                System.out.println(line);
            }

            System.out.println("----------------------------------------");
            System.out.println("Total packets read: " + totalPackets);
            System.out.println("Successfully parsed: " + parsedPackets);
            System.out.println("Forwarded: " + forwardedPackets);
            System.out.println("Dropped: " + droppedPackets);
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