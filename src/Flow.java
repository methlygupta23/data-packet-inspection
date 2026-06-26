// Flow.java
//
// Represents ONE ongoing connection (identified by a FiveTuple).
// Once we discover the SNI (domain name) for a connection, we store it
// here so every future packet on the same connection can reuse it -
// without needing to re-extract SNI every time (which wouldn't even
// be possible, since SNI only appears in the first packet).

public class Flow {

    public final FiveTuple fiveTuple;  // the "fingerprint" identifying this connection

    public String  sni;          // domain name, e.g. "www.youtube.com" - null until found
    public AppType appType;      // classified app, e.g. AppType.YOUTUBE
    public int      packetCount; // how many packets we've seen on this flow so far
    public boolean  blocked;     // will be set in Phase 5 (blocking rules)

    public Flow(FiveTuple fiveTuple) {
        this.fiveTuple   = fiveTuple;
        this.sni         = null;
        this.appType     = AppType.UNKNOWN;
        this.packetCount = 0;
        this.blocked     = false;
    }

    @Override
    public String toString() {
        return String.format("Flow[%s, sni=%s, app=%s, packets=%d, blocked=%b]",
                fiveTuple, sni, appType, packetCount, blocked);
    }
}