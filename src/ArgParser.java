// ArgParser.java
//
// Parses command-line arguments into a simple, easy-to-use structure.
//
// SUPPORTED USAGE:
//   java Main input.pcap
//   java Main input.pcap output.pcap
//   java Main input.pcap output.pcap --workers 8
//   java Main input.pcap output.pcap --block-app YOUTUBE --block-app FACEBOOK
//   java Main input.pcap output.pcap --block-domain facebook --block-ip 8.8.8.8
//
// Flags can be combined and repeated (e.g. multiple --block-app flags).

import java.util.ArrayList;
import java.util.List;

public class ArgParser {

    public String inputFile;
    public String outputFile = "output.pcap";
    public int numWorkers = 4;

    public final List<AppType> blockedApps = new ArrayList<>();
    public final List<String>  blockedDomains = new ArrayList<>();
    public final List<String>  blockedIps = new ArrayList<>();

    public static ArgParser parse(String[] args) {
        ArgParser result = new ArgParser();

        if (args.length < 1) {
            printUsageAndExit();
        }

        // Check for --help BEFORE treating args[0] as the input filename -
        // otherwise "java Main --help" would try to open a file named "--help".
        if (args[0].equals("--help")) {
            printUsageAndExit();
        }

        result.inputFile = args[0];
        int i = 1;

        // The second positional argument (output file) is only consumed
        // if it doesn't look like a flag (doesn't start with "--").
        if (i < args.length && !args[i].startsWith("--")) {
            result.outputFile = args[i];
            i++;
        }

        while (i < args.length) {
            String flag = args[i];

            switch (flag) {
                case "--workers":
                    requireValue(args, i, flag);
                    result.numWorkers = Integer.parseInt(args[i + 1]);
                    i += 2;
                    break;

                case "--block-app":
                    requireValue(args, i, flag);
                    result.blockedApps.add(parseAppType(args[i + 1]));
                    i += 2;
                    break;

                case "--block-domain":
                    requireValue(args, i, flag);
                    result.blockedDomains.add(args[i + 1]);
                    i += 2;
                    break;

                case "--block-ip":
                    requireValue(args, i, flag);
                    result.blockedIps.add(args[i + 1]);
                    i += 2;
                    break;

                case "--help":
                    printUsageAndExit();
                    break;

                default:
                    System.out.println("Unknown flag: " + flag);
                    printUsageAndExit();
            }
        }

        return result;
    }

    private static void requireValue(String[] args, int i, String flag) {
        if (i + 1 >= args.length) {
            System.out.println("Flag " + flag + " requires a value");
            printUsageAndExit();
        }
    }

    private static AppType parseAppType(String name) {
        try {
            return AppType.valueOf(name.toUpperCase());
        } catch (IllegalArgumentException e) {
            System.out.println("Unknown app type: " + name);
            System.out.println("Valid options: UNKNOWN, HTTP, HTTPS, DNS, YOUTUBE, FACEBOOK, "
                    + "GOOGLE, TIKTOK, INSTAGRAM, NETFLIX, GITHUB");
            System.exit(1);
            return null; // unreachable, keeps the compiler happy
        }
    }

    private static void printUsageAndExit() {
        System.out.println("Usage: java Main <input.pcap> [output.pcap] [options]");
        System.out.println();
        System.out.println("Options:");
        System.out.println("  --workers N             Number of worker threads (default: 4)");
        System.out.println("  --block-app APP         Block an app type (e.g. YOUTUBE). Repeatable.");
        System.out.println("  --block-domain TEXT     Block domains containing this text. Repeatable.");
        System.out.println("  --block-ip IP           Block a specific destination IP. Repeatable.");
        System.out.println("  --help                  Show this message");
        System.out.println();
        System.out.println("Example:");
        System.out.println("  java Main capture.pcap filtered.pcap --block-app YOUTUBE --block-domain facebook");
        System.exit(1);
    }
}