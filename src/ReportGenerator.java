// ReportGenerator.java
//
// Prints a clean, boxed summary of the capture analysis - final
// polished version with a proper border and aligned columns.

import java.util.HashMap;
import java.util.Map;

public class ReportGenerator {

    private static final int WIDTH = 50;

    public static void printReport(int totalPackets, int forwardedPackets,
                                    int droppedPackets, FlowTracker tracker,
                                    long elapsedMillis) {

        printBorder('=');
        printCentered("DPI ANALYSIS REPORT");
        printBorder('=');

        printRow("Total packets",   String.valueOf(totalPackets));
        printRow("Forwarded",       formatCount(forwardedPackets, totalPackets));
        printRow("Dropped",         formatCount(droppedPackets, totalPackets));
        printRow("Distinct flows",  String.valueOf(tracker.getFlowCount()));
        printRow("Processing time", elapsedMillis + " ms");

        printBorder('-');
        printCentered("Traffic by app type");
        printBorder('-');

        Map<AppType, Integer> packetsPerApp = new HashMap<>();
        for (Flow flow : tracker.getAllFlows().values()) {
            packetsPerApp.merge(flow.appType, flow.packetCount, Integer::sum);
        }

        // Sort by packet count, descending - most common traffic shown first
        packetsPerApp.entrySet().stream()
                .sorted((a, b) -> b.getValue() - a.getValue())
                .forEach(entry -> printRow(
                        "  " + entry.getKey(),
                        formatCount(entry.getValue(), totalPackets)));

        printBorder('=');
    }

    private static String formatCount(int part, int whole) {
        double pct = whole == 0 ? 0.0 : (100.0 * part) / whole;
        return part + " (" + String.format("%.1f", pct) + "%)";
    }

    private static void printRow(String label, String value) {
        System.out.printf("%-28s %20s%n", label, value);
    }

    private static void printCentered(String text) {
        int padding = Math.max(0, (WIDTH - text.length()) / 2);
        System.out.println(" ".repeat(padding) + text);
    }

    private static void printBorder(char ch) {
        System.out.println(String.valueOf(ch).repeat(WIDTH));
    }
}