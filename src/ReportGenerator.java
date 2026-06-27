// ReportGenerator.java
//
// Takes the final stats (packet counts) and the FlowTracker's flows,
// and prints a clean, human-readable summary table - similar to what
// a real traffic-monitoring tool would show you at the end of a run.

import java.util.HashMap;
import java.util.Map;

public class ReportGenerator {

    public static void printReport(int totalPackets, int forwardedPackets,
                                    int droppedPackets, FlowTracker tracker) {

        System.out.println();
        System.out.println("========================================");
        System.out.println("           DPI ANALYSIS REPORT");
        System.out.println("========================================");

        System.out.printf("%-25s %d%n", "Total packets:", totalPackets);
        System.out.printf("%-25s %d (%.1f%%)%n", "Forwarded:", forwardedPackets,
                percent(forwardedPackets, totalPackets));
        System.out.printf("%-25s %d (%.1f%%)%n", "Dropped:", droppedPackets,
                percent(droppedPackets, totalPackets));
        System.out.printf("%-25s %d%n", "Distinct flows:", tracker.getFlowCount());

        System.out.println("----------------------------------------");
        System.out.println("Traffic breakdown by app type:");
        System.out.println("----------------------------------------");

        // Count how many packets belong to each AppType across all flows
        Map<AppType, Integer> packetsPerApp = new HashMap<>();
        for (Flow flow : tracker.getAllFlows().values()) {
            packetsPerApp.merge(flow.appType, flow.packetCount, Integer::sum);
        }

        for (Map.Entry<AppType, Integer> entry : packetsPerApp.entrySet()) {
            double pct = percent(entry.getValue(), totalPackets);
            System.out.printf("  %-12s %5d packets  (%.1f%%)%n",
                    entry.getKey(), entry.getValue(), pct);
        }

        System.out.println("========================================");
    }

    private static double percent(int part, int whole) {
        if (whole == 0) return 0.0;
        return (100.0 * part) / whole;
    }
}