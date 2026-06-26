// RuleManager.java
//
// Holds three blocklists - by IP, by app type, and by domain keyword -
// and decides whether a given Flow should be blocked.
//
// HOW TO USE:
//   RuleManager rules = new RuleManager();
//   rules.blockApp(AppType.YOUTUBE);
//   rules.blockDomainContaining("facebook");
//   rules.blockIp("8.8.8.8");
//
//   if (rules.shouldBlock(flow)) {
//       flow.blocked = true;
//   }

import java.util.HashSet;
import java.util.Set;

public class RuleManager {

    private final Set<AppType> blockedApps = new HashSet<>();
    private final Set<Long>    blockedIps  = new HashSet<>();   // stored as 32-bit packed longs
    private final Set<String>  blockedDomainKeywords = new HashSet<>();

    // ---- Setup methods: call these before processing packets ----

    public void blockApp(AppType app) {
        blockedApps.add(app);
    }

    public void blockIp(String dottedIp) {
        blockedIps.add(ipStringToLong(dottedIp));
    }

    public void blockDomainContaining(String keyword) {
        blockedDomainKeywords.add(keyword.toLowerCase());
    }

    // ---- The actual decision logic ----
    //
    // Checks in this order: IP, then app type, then domain keyword.
    // Returns true the moment ANY rule matches - no need to check the rest.
    public boolean shouldBlock(Flow flow) {

        // 1. Check destination IP
        if (blockedIps.contains(flow.fiveTuple.dstIp)) {
            return true;
        }

        // 2. Check app type (only meaningful once we've classified it)
        if (flow.appType != null && blockedApps.contains(flow.appType)) {
            return true;
        }

        // 3. Check domain keyword (only meaningful once we have an SNI)
        if (flow.sni != null) {
            String hostname = flow.sni.toLowerCase();
            for (String keyword : blockedDomainKeywords) {
                if (hostname.contains(keyword)) {
                    return true;
                }
            }
        }

        return false;
    }

    // Converts "192.168.1.5" into the same packed-long format FiveTuple uses,
    // so we can compare directly against flow.fiveTuple.dstIp.
    private long ipStringToLong(String dottedIp) {
        String[] parts = dottedIp.split("\\.");
        long result = 0;
        for (String part : parts) {
            result = (result << 8) | (Long.parseLong(part) & 0xFF);
        }
        return result;
    }
}