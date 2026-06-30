// FlowTracker.java
//
// Keeps a HashMap<FiveTuple, Flow> - this is the "memory" of every
// connection we've seen so far. Lets us look up whether we already
// know the SNI/app for a given connection, without re-extracting it
// from every single packet.
//
// HOW TO USE:
//   FlowTracker tracker = new FlowTracker();
//   Flow flow = tracker.getOrCreateFlow(fiveTuple);
//   flow.packetCount++;
//   if (flow.sni == null) {
//       String hostname = SniExtractor.extract(payload);
//       if (hostname != null) {
//           tracker.recordSni(flow, hostname);
//       }
//   }

import java.util.HashMap;
import java.util.Map;

public class FlowTracker {

    // NOTE on thread-safety (Phase 8):
    // Multiple worker threads can call getOrCreateFlow() and recordSni()
    // AT THE SAME TIME, for different packets. Since they all share this
    // one HashMap, we mark these methods `synchronized` - meaning only
    // ONE thread can be running the synchronized code at any instant.
    // Other threads calling it simply wait their turn (briefly).
    // This is the simplest correct fix; Phase 9 improves on this by
    // giving each worker its own private map instead of sharing one.
    private final Map<FiveTuple, Flow> flows = new HashMap<>();

    // Looks up the Flow for this five-tuple. If we've never seen this
    // connection before, creates a brand new Flow and stores it.
    public synchronized Flow getOrCreateFlow(FiveTuple key) {
        Flow flow = flows.get(key);
        if (flow == null) {
            flow = new Flow(key);
            flows.put(key, flow);
        }
        return flow;
    }

    // classifyAppType doesn't touch the shared HashMap at all - it's pure
    // logic on a hostname string - so it's `static` and does NOT need to
    // be synchronized. This also means WorkerThread can call it directly
    // while already holding a Flow's lock, without any risk of acquiring
    // two locks in conflicting order (the deadlock we hit and fixed).
    public static AppType classifyAppType(String hostname) {
        String h = hostname.toLowerCase();

        if (h.contains("youtube") || h.contains("ytimg") || h.contains("googlevideo")) {
            return AppType.YOUTUBE;
        }
        if (h.contains("facebook") || h.contains("fbcdn")) {
            return AppType.FACEBOOK;
        }
        if (h.contains("instagram")) {
            return AppType.INSTAGRAM;
        }
        if (h.contains("tiktok") || h.contains("musical.ly") || h.contains("tiktokcdn")) {
            return AppType.TIKTOK;
        }
        if (h.contains("netflix") || h.contains("nflxvideo")) {
            return AppType.NETFLIX;
        }
        if (h.contains("github")) {
            return AppType.GITHUB;
        }
        if (h.contains("google")) {
            return AppType.GOOGLE;
        }
        return AppType.HTTPS; // we know it's HTTPS, just not which app
    }

    // Useful for Phase 6 (reporting) - gives access to every tracked flow.
    public synchronized Map<FiveTuple, Flow> getAllFlows() {
        return flows;
    }

    public synchronized int getFlowCount() {
        return flows.size();
    }
}