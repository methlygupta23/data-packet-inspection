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

    private final Map<FiveTuple, Flow> flows = new HashMap<>();

    // Looks up the Flow for this five-tuple. If we've never seen this
    // connection before, creates a brand new Flow and stores it.
    public Flow getOrCreateFlow(FiveTuple key) {
        Flow flow = flows.get(key);
        if (flow == null) {
            flow = new Flow(key);
            flows.put(key, flow);
        }
        return flow;
    }

    // Call this once we've successfully extracted an SNI for a flow.
    // Also classifies the app type based on the hostname.
    public void recordSni(Flow flow, String hostname) {
        flow.sni = hostname;
        flow.appType = classifyAppType(hostname);
    }

    // Very simple classifier: checks if known app names appear as a
    // substring of the hostname. Good enough for common cases like
    // "www.youtube.com" or "m.facebook.com".
    private AppType classifyAppType(String hostname) {
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
    public Map<FiveTuple, Flow> getAllFlows() {
        return flows;
    }

    public int getFlowCount() {
        return flows.size();
    }
}