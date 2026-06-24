// AppType.java
// An enum is just a fixed set of named constants.
// We use this so we can say "this flow is YOUTUBE" instead of using
// magic strings like "youtube" scattered everywhere in the code.

public enum AppType {
    UNKNOWN,    // haven't identified it yet
    HTTP,       // plain unencrypted web traffic
    HTTPS,      // encrypted web — we know it's HTTPS but not which app
    DNS,        // domain name lookups
    YOUTUBE,
    FACEBOOK,
    GOOGLE,
    TIKTOK,
    INSTAGRAM,
    NETFLIX,
    GITHUB
}