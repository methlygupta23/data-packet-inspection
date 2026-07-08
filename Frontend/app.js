// app.js
// JavaScript implementation of the DPI Engine pipeline and interactive visualization.

// ==========================================
// 1. PACKET PRESETS & DATA DEFINITIONS
// ==========================================

const PACKET_PRESETS = {
    youtube: [
        // Ethernet Header (14 bytes)
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Dst MAC (0-5)
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, // Src MAC (6-11)
        0x08, 0x00,                         // EtherType IPv4 (12-13)

        // IP Header (20 bytes)
        0x45, 0x00, 0x00, 0x70,             // IP: Version, IHL, Total Len (112)
        0x12, 0x34, 0x40, 0x00,             // IP: ID, Flags/Fragment Offset (DF=1)
        0x40, 0x06, 0x00, 0x00,             // IP: TTL (64), TCP Protocol (6), Checksum
        0xc0, 0xa8, 0x01, 0x0f,             // IP: Src IP (192.168.1.15)
        0xac, 0xd9, 0x10, 0x8e,             // IP: Dst IP (172.217.16.142 - YouTube)

        // TCP Header (20 bytes)
        0xc0, 0x00, 0x01, 0xbb,             // TCP: Src Port (49152), Dst Port (443 - HTTPS)
        0x00, 0x00, 0x00, 0x01,             // TCP: Seq Num
        0x00, 0x00, 0x00, 0x01,             // TCP: Ack Num
        0x50, 0x18, 0xfa, 0xf0,             // TCP: Offset (20 bytes), Flags (PSH, ACK)
        0x00, 0x00, 0x00, 0x00,             // TCP: Checksum, Urgent Pointer

        // TLS Payload (TLS Record Header - 5 bytes)
        0x16, 0x03, 0x01, 0x00, 0x3d,       // TLS Handshake, TLS 1.0, Length (61)

        // Handshake Protocol (Client Hello - 4 bytes)
        0x01, 0x00, 0x00, 0x39,             // Client Hello Type, Length (57)

        // Client Hello body (53 bytes)
        0x03, 0x03,                         // Version (TLS 1.2)
        // Random (32 bytes)
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        0x00,                               // Session ID Length (0)
        0x00, 0x02, 0x00, 0x2f,             // Cipher Suites Length (2), Suite (0x002f)
        0x01, 0x00,                         // Compression Length (1), Null (0)
        0x00, 0x12,                         // Extensions Length (18)

        // SNI Extension
        0x00, 0x00, 0x00, 0x0e,             // Extension Type (0x0000), Ext Length (14)
        0x00, 0x0c, 0x00,                   // SNI Entry: List length 12, Type Hostname (0)
        0x00, 0x0b,                         // Hostname Length (11)
        // Hostname: "youtube.com" (11 bytes)
        0x79, 0x6f, 0x75, 0x74, 0x75, 0x62, 0x65, 0x2e, 0x63, 0x6f, 0x6d
    ],
    github: [
        // Ethernet Header (14 bytes)
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 
        0x08, 0x00, 

        // IP Header (20 bytes)
        0x45, 0x00, 0x00, 0x6d, 
        0x56, 0x78, 0x40, 0x00, 
        0x40, 0x06, 0x00, 0x00, 
        0xc0, 0xa8, 0x01, 0x0f, 
        0x8c, 0x52, 0x70, 0x04,             // Dst IP: 140.82.112.4 (GitHub)

        // TCP Header (20 bytes)
        0xc0, 0x02, 0x01, 0xbb,             // Dst Port: 443 (HTTPS)
        0x00, 0x00, 0x00, 0x01, 
        0x00, 0x00, 0x00, 0x01, 
        0x50, 0x18, 0xfa, 0xf0, 
        0x00, 0x00, 0x00, 0x00, 

        // TLS Payload (TLS Record Header - 5 bytes)
        0x16, 0x03, 0x01, 0x00, 0x3a,       // TLS Handshake, TLS 1.0, Length (58)

        // Handshake Protocol (Client Hello - 4 bytes)
        0x01, 0x00, 0x00, 0x36,             // Client Hello Type, Length (54)

        // Client Hello body (50 bytes)
        0x03, 0x03, 
        // Random (32 bytes)
        0xaa, 0xbb, 0xcc, 0xdd, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        0x00, 
        0x00, 0x02, 0x00, 0x2f, 
        0x01, 0x00, 
        0x00, 0x11,                         // Extensions Length (17)

        // SNI Extension
        0x00, 0x00, 0x00, 0x0d,             // Extension Type (0x0000), Ext Length (13)
        0x00, 0x0b, 0x00,                   // SNI Entry: List length 11, Type Hostname (0)
        0x00, 0x0a,                         // Hostname Length (10)
        // Hostname: "github.com" (10 bytes)
        0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d
    ],
    http: [
        // Ethernet Header
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 
        0x08, 0x00, 

        // IP Header
        0x45, 0x00, 0x00, 0x54, 
        0xaa, 0xbb, 0x40, 0x00, 
        0x40, 0x06, 0x00, 0x00, 
        0xc0, 0xa8, 0x01, 0x0f, 
        0x5d, 0xb8, 0xd8, 0x22,             // Dst IP: 93.184.216.34 (example.com)

        // TCP Header
        0xc0, 0x05, 0x00, 0x50,             // Dst Port: 80 (HTTP)
        0x00, 0x00, 0x00, 0x02, 
        0x00, 0x00, 0x00, 0x02, 
        0x50, 0x18, 0xfa, 0xf0, 
        0x00, 0x00, 0x00, 0x00, 

        // Payload: "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" (40 bytes)
        0x47, 0x45, 0x54, 0x20, 0x2f, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0x0d, 0x0a,
        0x48, 0x6f, 0x73, 0x74, 0x3a, 0x20, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 
        0x6d, 0x0d, 0x0a, 0x0d, 0x0a
    ],
    dns: [
        // Ethernet Header
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 
        0x08, 0x00, 

        // IP Header
        0x45, 0x00, 0x00, 0x40, 
        0x99, 0x88, 0x00, 0x00, 
        0x40, 0x11, 0x00, 0x00,             // Protocol: 17 (UDP - 0x11)
        0xc0, 0xa8, 0x01, 0x0f, 
        0x08, 0x08, 0x08, 0x08,             // Dst IP: 8.8.8.8 (DNS Server)

        // UDP Header (8 bytes)
        0xc8, 0x22, 0x00, 0x35,             // Src Port 51234, Dst Port 53 (DNS)
        0x00, 0x2c, 0x00, 0x00,             // UDP Length (44), Checksum (0)

        // DNS Query Payload (36 bytes)
        0x24, 0x1a, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x06, 0x67, 0x6f, 0x6f, 
        0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 
        0x00, 0x01, 0x00, 0x01
    ],
    ipv6: [
        // Ethernet Header
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 
        0x86, 0xdd,                         // EtherType IPv6 (0x86dd)

        // IPv6 Header & Payload (mock data for visualization)
        0x60, 0x00, 0x00, 0x00, 0x00, 0x20, 0x06, 0x40,
        0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x02, 0x11, 0x2f, 0xff, 0xfe, 0x34, 0x56, 0x78,
        0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x88
    ],
    malformed: [
        // Only 8 bytes (too short to have an EtherType or IP header)
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77
    ]
};

// Map of categories and preset indices for classification
const RANDOM_PRESETS = ['youtube', 'github', 'http', 'dns', 'ipv6', 'malformed'];

// ==========================================
// 2. STATE MANAGER & RULE ENGINE
// ==========================================

const state = {
    // Engine Config
    workersCount: 4,
    simSpeed: 1.0,
    isPlaying: false,
    
    // Blocking Rules
    blockedApps: new Set(),
    blockedDomains: new Set(),
    blockedIps: new Set(),

    // Statistics
    processedCount: 0,
    allowedCount: 0,
    droppedCount: 0,
    throughputRate: 0,
    
    // App Classification Counters
    appClassifier: {
        YOUTUBE: 0,
        FACEBOOK: 0,
        GITHUB: 0,
        TIKTOK: 0,
        INSTAGRAM: 0,
        NETFLIX: 0,
        HTTP: 0,
        DNS: 0,
        UNKNOWN: 0
    },

    // Worker Thread Loads
    workerThreads: [], // Array of { id, processed, queue: [], active: false }

    // Active packet animations in SVG
    activePackets: [],
    
    // Active UI elements
    selectedPresetKey: 'youtube'
};

// ==========================================
// 3. PACKET PARSER & SNI EXTRACTOR (JS PORT)
// ==========================================

function formatIp(ipNum) {
    return `${(ipNum >>> 24) & 0xFF}.${(ipNum >>> 16) & 0xFF}.${(ipNum >>> 8) & 0xFF}.${ipNum & 0xFF}`;
}

function parsePacket(bytes) {
    if (!bytes || bytes.length < 14) {
        return { valid: false, error: "Malformed (too short for Ethernet header)" };
    }

    const parsed = {
        valid: true,
        etherType: (bytes[12] << 8) | bytes[13],
        isIp: false,
        isTcp: false,
        isUdp: false,
        srcIp: 0,
        dstIp: 0,
        srcPort: 0,
        dstPort: 0,
        protocol: 0,
        payloadOffset: 0,
        sni: null,
        appType: "UNKNOWN",
        // Byte ranges for visualization highlights
        ranges: {
            eth: [0, 13],
            ip: null,
            tcpudp: null,
            tls: null,
            payload: null
        }
    };

    if (parsed.etherType !== 0x0800) {
        return {
            ...parsed,
            valid: false,
            error: `Unsupported EtherType (0x${parsed.etherType.toString(16).toUpperCase()}). Only IPv4 (0x0800) supported.`
        };
    }

    // IP Header
    parsed.isIp = true;
    const ipStart = 14;
    if (bytes.length < ipStart + 20) {
        parsed.valid = false;
        parsed.error = "IP Header truncated";
        return parsed;
    }

    const versionAndHeaderLen = bytes[ipStart];
    const ipHeaderLen = (versionAndHeaderLen & 0x0F) * 4;
    if (ipHeaderLen < 20 || bytes.length < ipStart + ipHeaderLen) {
        parsed.valid = false;
        parsed.error = "Invalid IP Header Length";
        return parsed;
    }
    
    parsed.ranges.ip = [ipStart, ipStart + ipHeaderLen - 1];
    
    parsed.protocol = bytes[ipStart + 9];
    parsed.srcIp = (bytes[ipStart + 12] << 24) | (bytes[ipStart + 13] << 16) | (bytes[ipStart + 14] << 8) | bytes[ipStart + 15];
    parsed.dstIp = (bytes[ipStart + 16] << 24) | (bytes[ipStart + 17] << 16) | (bytes[ipStart + 18] << 8) | bytes[ipStart + 19];

    const afterIp = ipStart + ipHeaderLen;

    if (parsed.protocol === 6) {
        // TCP
        parsed.isTcp = true;
        if (bytes.length < afterIp + 20) {
            parsed.valid = false;
            parsed.error = "TCP Header truncated";
            return parsed;
        }

        parsed.srcPort = (bytes[afterIp] << 8) | bytes[afterIp + 1];
        parsed.dstPort = (bytes[afterIp + 2] << 8) | bytes[afterIp + 3];

        const tcpHeaderLen = ((bytes[afterIp + 12] & 0xFF) >> 4) * 4;
        if (tcpHeaderLen < 20 || bytes.length < afterIp + tcpHeaderLen) {
            parsed.valid = false;
            parsed.error = "Invalid TCP Header Length";
            return parsed;
        }

        parsed.ranges.tcpudp = [afterIp, afterIp + tcpHeaderLen - 1];
        parsed.payloadOffset = afterIp + tcpHeaderLen;
        parsed.appType = "HTTP"; // Default for TCP traffic in this project if not TLS
    } else if (parsed.protocol === 17) {
        // UDP
        parsed.isUdp = true;
        if (bytes.length < afterIp + 8) {
            parsed.valid = false;
            parsed.error = "UDP Header truncated";
            return parsed;
        }

        parsed.srcPort = (bytes[afterIp] << 8) | bytes[afterIp + 1];
        parsed.dstPort = (bytes[afterIp + 2] << 8) | bytes[afterIp + 3];
        parsed.ranges.tcpudp = [afterIp, afterIp + 7];
        parsed.payloadOffset = afterIp + 8;
        parsed.appType = parsed.dstPort === 53 || parsed.srcPort === 53 ? "DNS" : "UNKNOWN";
    } else {
        parsed.valid = false;
        parsed.error = `Unsupported protocol number ${parsed.protocol} (Not TCP/UDP)`;
        return parsed;
    }

    // TLS SNI Extraction
    if (parsed.isTcp && parsed.dstPort === 443) {
        parsed.appType = "HTTPS";
        const payload = bytes.slice(parsed.payloadOffset);
        if (payload.length >= 6) {
            try {
                const hostname = extractSni(payload);
                if (hostname) {
                    parsed.sni = hostname;
                    parsed.appType = classifyAppType(hostname);
                    parsed.ranges.tls = [parsed.payloadOffset, bytes.length - 1];
                }
            } catch (e) {
                // Ignore parsing exceptions, leave SNI null
            }
        }
    }

    if (parsed.payloadOffset < bytes.length && !parsed.ranges.tls) {
        parsed.ranges.payload = [parsed.payloadOffset, bytes.length - 1];
    }

    return parsed;
}

function extractSni(data) {
    let pos = 0;

    // TLS Record Header (5 bytes)
    const recordType = data[pos] & 0xFF;
    if (recordType !== 0x16) return null; // Not handshake
    pos += 5;

    // Handshake Type
    if (pos >= data.length) return null;
    const handshakeType = data[pos] & 0xFF;
    if (handshakeType !== 0x01) return null; // Not Client Hello
    pos += 4;

    // Client Hello Body
    pos += 2;  // version
    pos += 32; // random

    if (pos >= data.length) return null;
    const sessionIdLen = data[pos] & 0xFF;
    pos += 1 + sessionIdLen;

    if (pos + 2 > data.length) return null;
    const cipherSuitesLen = (data[pos] << 8) | data[pos + 1];
    pos += 2 + cipherSuitesLen;

    if (pos >= data.length) return null;
    const compressionMethodsLen = data[pos] & 0xFF;
    pos += 1 + compressionMethodsLen;

    if (pos + 2 > data.length) return null;
    const extensionsLen = (data[pos] << 8) | data[pos + 1];
    pos += 2;

    const extensionsEnd = pos + extensionsLen;
    const limit = Math.min(extensionsEnd, data.length);

    while (pos + 4 <= limit) {
        const extType = (data[pos] << 8) | data[pos + 1];
        const extLen  = (data[pos + 2] << 8) | data[pos + 3];
        const extDataStart = pos + 4;

        if (extType === 0x0000) {
            // Found SNI!
            return parseServerNameExtension(data, extDataStart, extLen);
        }
        pos = extDataStart + extLen;
    }
    return null;
}

function parseServerNameExtension(data, start, extLen) {
    if (start + 5 > data.length) return null;
    const nameType = data[start + 2] & 0xFF;
    if (nameType !== 0x00) return null;

    const hostnameLen = (data[start + 3] << 8) | data[start + 4];
    const hostnameStart = start + 5;
    if (hostnameStart + hostnameLen > data.length) return null;

    let hostStr = "";
    for (let i = 0; i < hostnameLen; i++) {
        hostStr += String.fromCharCode(data[hostnameStart + i]);
    }
    return hostStr;
}

function classifyAppType(hostname) {
    const host = hostname.toLowerCase();
    if (host.includes("youtube.com") || host.includes("googlevideo.com") || host.includes("ytimg.com")) return "YOUTUBE";
    if (host.includes("facebook.com") || host.includes("fbcdn.net")) return "FACEBOOK";
    if (host.includes("github.com") || host.includes("githubusercontent.com")) return "GITHUB";
    if (host.includes("tiktok.com") || host.includes("byteoversea.com")) return "TIKTOK";
    if (host.includes("instagram.com") || host.includes("cdninstagram.com")) return "INSTAGRAM";
    if (host.includes("netflix.com") || host.includes("nflximg.net") || host.includes("nflxvideo.net")) return "NETFLIX";
    if (host.includes("google.com") || host.includes("gstatic.com") || host.includes("apis.google.com")) return "GOOGLE";
    return "HTTPS";
}

function computeQuickHash(bytes) {
    if (!bytes || bytes.length < 34) return 0;
    
    // Quick flow hash matches QuickFlowHash.java
    const etherType = (bytes[12] << 8) | bytes[13];
    if (etherType !== 0x0800) return 0;

    const ipStart = 14;
    const versionAndHeaderLen = bytes[ipStart];
    const ipHeaderLen = (versionAndHeaderLen & 0x0F) * 4;

    if (ipHeaderLen < 20 || bytes.length < ipStart + ipHeaderLen + 4) return 0;

    const bytesToInt = (offset) => {
        return (bytes[offset] << 24) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3];
    };

    const srcIp = bytesToInt(ipStart + 12);
    const dstIp = bytesToInt(ipStart + 16);

    const afterIp = ipStart + ipHeaderLen;
    let srcPort = 0;
    let dstPort = 0;

    if (bytes.length >= afterIp + 4) {
        srcPort = (bytes[afterIp] << 8) | bytes[afterIp + 1];
        dstPort = (bytes[afterIp + 2] << 8) | bytes[afterIp + 3];
    }

    let hash = srcIp;
    hash = Math.imul(hash, 31) + dstIp;
    hash = Math.imul(hash, 31) + srcPort;
    hash = Math.imul(hash, 31) + dstPort;
    return hash;
}

// Check rules
function shouldBlock(parsed) {
    if (!parsed || !parsed.valid) return false;

    // 1. IP
    if (state.blockedIps.has(formatIp(parsed.dstIp))) {
        return true;
    }

    // 2. App Type
    if (parsed.appType && state.blockedApps.has(parsed.appType)) {
        return true;
    }

    // 3. Domain
    if (parsed.sni) {
        const sniLower = parsed.sni.toLowerCase();
        for (const kw of state.blockedDomains) {
            if (sniLower.includes(kw)) {
                return true;
            }
        }
    }

    return false;
}

// ==========================================
// 4. UI RENDERERS & EVENT HANDLERS
// ==========================================

function updateStatsUI() {
    document.getElementById('stat-total').innerText = state.processedCount;
    document.getElementById('stat-allowed').innerText = state.allowedCount;
    document.getElementById('stat-dropped').innerText = state.droppedCount;
    document.getElementById('stat-rate').innerText = state.throughputRate.toFixed(1) + " p/s";

    const allowedPct = state.processedCount > 0 ? Math.round((state.allowedCount / state.processedCount) * 100) : 0;
    const droppedPct = state.processedCount > 0 ? Math.round((state.droppedCount / state.processedCount) * 100) : 0;

    document.getElementById('pct-allowed').innerText = `${allowedPct}%`;
    document.getElementById('pct-dropped').innerText = `${droppedPct}%`;
    
    renderAppDistribution();
    renderWorkersLoad();
}

function renderActiveRules() {
    const list = document.getElementById('active-rules');
    list.innerHTML = "";

    let hasRules = false;

    // Blocked Apps
    state.blockedApps.forEach(app => {
        hasRules = true;
        const li = document.createElement('li');
        li.innerHTML = `
            <span>Block App: <strong>${app}</strong></span>
            <button class="delete-rule" data-type="app" data-value="${app}"><i data-lucide="trash-2"></i></button>
        `;
        list.appendChild(li);
    });

    // Blocked Domains
    state.blockedDomains.forEach(kw => {
        hasRules = true;
        const li = document.createElement('li');
        li.innerHTML = `
            <span>Block Domain keyword: <strong>"${kw}"</strong></span>
            <button class="delete-rule" data-type="domain" data-value="${kw}"><i data-lucide="trash-2"></i></button>
        `;
        list.appendChild(li);
    });

    // Blocked IPs
    state.blockedIps.forEach(ip => {
        hasRules = true;
        const li = document.createElement('li');
        li.innerHTML = `
            <span>Block IP: <strong>${ip}</strong></span>
            <button class="delete-rule" data-type="ip" data-value="${ip}"><i data-lucide="trash-2"></i></button>
        `;
        list.appendChild(li);
    });

    if (!hasRules) {
        list.innerHTML = '<li class="empty-rules">No blocking rules active. All traffic allowed.</li>';
    } else {
        // Reinitialize icons for newly added buttons
        lucide.createIcons();
    }
}

function renderAppDistribution() {
    const container = document.getElementById('app-dist-container');
    container.innerHTML = "";

    const sortedApps = Object.entries(state.appClassifier)
        .sort((a, b) => b[1] - a[1]);

    const maxCount = Math.max(...sortedApps.map(e => e[1]), 1);

    sortedApps.forEach(([app, count]) => {
        const pct = Math.round((count / (state.processedCount || 1)) * 100);
        const item = document.createElement('div');
        item.className = "app-dist-item";
        item.innerHTML = `
            <div class="app-dist-header">
                <span class="app-dist-name">${app}</span>
                <span class="app-dist-count">${count} (${pct}%)</span>
            </div>
            <div class="app-bar-bg">
                <div class="app-bar-fill ${app.toLowerCase()}" style="width: ${(count / maxCount * 100)}%"></div>
            </div>
        `;
        container.appendChild(item);
    });
}

function renderWorkersLoad() {
    const container = document.getElementById('workers-load-container');
    container.innerHTML = "";

    state.workerThreads.forEach((w, idx) => {
        const qSize = w.queue.length;
        const pct = Math.min((qSize / 10) * 100, 100); // 10 is max capacity for display warnings
        const activeClass = w.active ? "worker-status-active" : "worker-status-idle";
        const statusText = w.active ? "Working" : "Idle";
        
        let warnClass = "normal";
        if (qSize > 7) warnClass = "danger";
        else if (qSize > 4) warnClass = "warning";

        const div = document.createElement('div');
        div.className = "worker-load-item";
        div.innerHTML = `
            <span class="worker-name">Worker-${idx}</span>
            <span class="worker-status ${activeClass}">${statusText}</span>
            <div class="worker-queue-visual">
                <span class="queue-label-text">Q: ${qSize}</span>
                <div class="progress-bar-bg">
                    <div class="progress-bar-fill ${warnClass}" style="width: ${pct}%; background-color: ${
                        warnClass === 'danger' ? 'var(--color-red)' : 
                        warnClass === 'warning' ? 'var(--color-orange)' : 'var(--color-teal)'
                    }"></div>
                </div>
            </div>
            <span class="worker-pcount">${w.processed} pkts</span>
        `;
        container.appendChild(div);
    });
}

function updateHexViewer(presetKey) {
    const bytes = PACKET_PRESETS[presetKey];
    const grid = document.getElementById('hex-grid');
    grid.innerHTML = "";

    const parsed = parsePacket(bytes);
    
    // Helper to identify range
    const getLayerClass = (idx) => {
        if (!parsed.valid) return "layer-payload";
        const r = parsed.ranges;
        if (r.eth && idx >= r.eth[0] && idx <= r.eth[1]) return "layer-eth";
        if (r.ip && idx >= r.ip[0] && idx <= r.ip[1]) return "layer-ip";
        if (r.tcpudp && idx >= r.tcpudp[0] && idx <= r.tcpudp[1]) return "layer-tcpudp";
        if (r.tls && idx >= r.tls[0] && idx <= r.tls[1]) return "layer-tls";
        return "layer-payload";
    };

    let lineHtml = "";
    for (let i = 0; i < bytes.length; i += 16) {
        const offset = i.toString(16).toUpperCase().padStart(4, '0');
        
        let hexGroup = "";
        let asciiGroup = "";

        for (let j = 0; j < 16; j++) {
            const idx = i + j;
            if (idx < bytes.length) {
                const b = bytes[idx];
                const hexVal = b.toString(16).toUpperCase().padStart(2, '0');
                const charVal = (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.';
                const layerClass = getLayerClass(idx);

                hexGroup += `<span class="hex-byte ${layerClass}" data-index="${idx}">${hexVal}</span>`;
                asciiGroup += `<span class="hex-ascii ${layerClass}" data-index="${idx}">${charVal === '<' ? '&lt;' : (charVal === '>' ? '&gt;' : charVal)}</span>`;
            } else {
                hexGroup += `<span class="hex-byte empty">&nbsp;&nbsp;</span>`;
                asciiGroup += `<span class="hex-ascii empty">&nbsp;</span>`;
            }
        }

        lineHtml += `
            <div class="hex-line">
                <span class="hex-offset">${offset}</span>
                <div class="hex-bytes-group">${hexGroup}</div>
                <div class="hex-ascii-group">${asciiGroup}</div>
            </div>
        `;
    }
    grid.innerHTML = lineHtml;

    // Hover listeners
    const hexBytes = grid.querySelectorAll('.hex-byte, .hex-ascii');
    hexBytes.forEach(span => {
        span.addEventListener('mouseenter', () => {
            const idx = parseInt(span.getAttribute('data-index'));
            if (isNaN(idx)) return;
            const lClass = getLayerClass(idx);
            
            // Highlight all elements of this class
            grid.querySelectorAll(`.${lClass}`).forEach(el => el.classList.add('hovered'));
            
            // Describe header
            describeHoverRange(lClass, idx, parsed);
        });

        span.addEventListener('mouseleave', () => {
            const idx = parseInt(span.getAttribute('data-index'));
            if (isNaN(idx)) return;
            const lClass = getLayerClass(idx);
            grid.querySelectorAll(`.${lClass}`).forEach(el => el.classList.remove('hovered'));
            document.getElementById('hex-hover-info').innerText = "Hover bytes to inspect headers";
        });
    });

    renderDecodeBreakdown(parsed);
}

function describeHoverRange(layerClass, idx, parsed) {
    const legend = document.getElementById('hex-hover-info');
    
    if (layerClass === 'layer-eth') {
        if (idx <= 5) legend.innerText = "Ethernet Header: Destination MAC Address";
        else if (idx <= 11) legend.innerText = "Ethernet Header: Source MAC Address";
        else legend.innerText = `Ethernet Header: EtherType (0x${parsed.etherType.toString(16).toUpperCase()} = IPv4)`;
    } else if (layerClass === 'layer-ip') {
        const ipStart = 14;
        const subOffset = idx - ipStart;
        if (subOffset === 0) legend.innerText = "IP Header: Version & Internet Header Length (IHL)";
        else if (subOffset === 1) legend.innerText = "IP Header: Differentiated Services Code Point (DSCP)";
        else if (subOffset <= 3) legend.innerText = "IP Header: Total Length field";
        else if (subOffset <= 5) legend.innerText = "IP Header: Packet Identification (ID)";
        else if (subOffset <= 7) legend.innerText = "IP Header: Flags & Fragment Offset";
        else if (subOffset === 8) legend.innerText = "IP Header: Time to Live (TTL) hop limit";
        else if (subOffset === 9) legend.innerText = `IP Header: Protocol (0x${parsed.protocol.toString(16).padStart(2,'0')} = ${parsed.protocol === 6 ? 'TCP' : 'UDP'})`;
        else if (subOffset <= 11) legend.innerText = "IP Header: Header Checksum";
        else if (subOffset <= 15) legend.innerText = `IP Header: Source IP Address (${formatIp(parsed.srcIp)})`;
        else if (subOffset <= 19) legend.innerText = `IP Header: Destination IP Address (${formatIp(parsed.dstIp)})`;
        else legend.innerText = "IP Header Options/Padding";
    } else if (layerClass === 'layer-tcpudp') {
        const tcpudpStart = parsed.ranges.tcpudp[0];
        const subOffset = idx - tcpudpStart;
        
        if (parsed.isTcp) {
            if (subOffset <= 1) legend.innerText = `TCP Header: Source Port (${parsed.srcPort})`;
            else if (subOffset <= 3) legend.innerText = `TCP Header: Destination Port (${parsed.dstPort})`;
            else if (subOffset <= 7) legend.innerText = "TCP Header: Sequence Number (Flow alignment)";
            else if (subOffset <= 11) legend.innerText = "TCP Header: Acknowledgment Number";
            else if (subOffset === 12) legend.innerText = "TCP Header: Data Offset (Header size length)";
            else if (subOffset === 13) legend.innerText = "TCP Header: Flags (SYN, ACK, PSH, FIN etc)";
            else if (subOffset <= 15) legend.innerText = "TCP Header: Receiver Window Size";
            else if (subOffset <= 17) legend.innerText = "TCP Header: Segment Checksum";
            else legend.innerText = "TCP Header Options (MSS, TS, SACK)";
        } else {
            if (subOffset <= 1) legend.innerText = `UDP Header: Source Port (${parsed.srcPort})`;
            else if (subOffset <= 3) legend.innerText = `UDP Header: Destination Port (${parsed.dstPort})`;
            else if (subOffset <= 5) legend.innerText = "UDP Header: Length of datagram";
            else legend.innerText = "UDP Header: Checksum";
        }
    } else if (layerClass === 'layer-tls') {
        const tlsStart = parsed.payloadOffset;
        const subOffset = idx - tlsStart;
        if (subOffset === 0) legend.innerText = "TLS Record Header: Content Type (0x16 = Handshake)";
        else if (subOffset <= 2) legend.innerText = "TLS Record Header: SSL/TLS Protocol Version";
        else if (subOffset <= 4) legend.innerText = "TLS Record Header: Record Length";
        else if (subOffset === 5) legend.innerText = "TLS Handshake: Message Type (0x01 = Client Hello)";
        else if (subOffset <= 8) legend.innerText = "TLS Handshake: Payload Length";
        else if (subOffset <= 10) legend.innerText = "TLS Handshake: Client Hello Version";
        else if (subOffset <= 42) legend.innerText = "TLS Handshake: Secure Random bytes";
        else if (idx >= parsed.ranges.tls[1] - parsed.sni.length) legend.innerText = `TLS SNI Extension: Hostname String ("${parsed.sni}")`;
        else legend.innerText = "TLS Client Hello Extension data (Ciphers/Extensions)";
    } else {
        legend.innerText = "Application Payload data";
    }
}

function renderDecodeBreakdown(parsed) {
    const card = document.getElementById('decode-details');
    card.innerHTML = "";

    if (!parsed.valid) {
        card.innerHTML = `
            <div class="decode-layer">
                <div class="decode-layer-title layer-title-rules">
                    <i data-lucide="alert-triangle"></i> Parsing Failed / Ignored
                </div>
                <div class="help-text" style="color:var(--color-red)">
                    ${parsed.error || "Packet is too small or does not match IPv4 Ethernet framing. In the Java pipeline, PacketParser returns null and the packet is forwarded directly without inspection."}
                </div>
            </div>
        `;
        lucide.createIcons();
        return;
    }

    // Layer 1
    const l1 = document.createElement('div');
    l1.className = "decode-layer";
    l1.innerHTML = `
        <div class="decode-layer-title layer-title-eth">
            <i data-lucide="layers"></i> Layer 1: Ethernet Frame
        </div>
        <div class="decode-fields">
            <div class="decode-field"><span>EtherType:</span> <span>0x${parsed.etherType.toString(16).toUpperCase()} (IPv4)</span></div>
        </div>
    `;
    card.appendChild(l1);

    // Layer 2
    const l2 = document.createElement('div');
    l2.className = "decode-layer";
    l2.innerHTML = `
        <div class="decode-layer-title layer-title-ip">
            <i data-lucide="globe"></i> Layer 2: IP Header
        </div>
        <div class="decode-fields">
            <div class="decode-field"><span>Src IP:</span> <span>${formatIp(parsed.srcIp)}</span></div>
            <div class="decode-field"><span>Dst IP:</span> <span>${formatIp(parsed.dstIp)}</span></div>
            <div class="decode-field"><span>Protocol:</span> <span>${parsed.protocol} (${parsed.isTcp ? 'TCP' : 'UDP'})</span></div>
        </div>
    `;
    card.appendChild(l2);

    // Layer 3
    const l3 = document.createElement('div');
    l3.className = "decode-layer";
    l3.innerHTML = `
        <div class="decode-layer-title layer-title-tcp">
            <i data-lucide="hash"></i> Layer 3: ${parsed.isTcp ? 'TCP Segment' : 'UDP Datagram'}
        </div>
        <div class="decode-fields">
            <div class="decode-field"><span>Src Port:</span> <span>${parsed.srcPort}</span></div>
            <div class="decode-field"><span>Dst Port:</span> <span>${parsed.dstPort}</span></div>
        </div>
    `;
    card.appendChild(l3);

    // Layer 4
    if (parsed.sni) {
        const l4 = document.createElement('div');
        l4.className = "decode-layer";
        l4.innerHTML = `
            <div class="decode-layer-title layer-title-tls">
                <i data-lucide="lock"></i> Layer 4: TLS SNI Extractor
            </div>
            <div class="decode-fields">
                <div class="decode-field"><span>Extracted SNI:</span> <span style="color:var(--color-yellow)">${parsed.sni}</span></div>
                <div class="decode-field"><span>Classified App:</span> <span class="badge badge-teal">${parsed.appType}</span></div>
            </div>
        `;
        card.appendChild(l4);
    }

    // Rules Evaluation
    const rulesMatched = shouldBlock(parsed);
    const lRules = document.createElement('div');
    lRules.className = "decode-layer";
    lRules.innerHTML = `
        <div class="decode-layer-title layer-title-rules">
            <i data-lucide="shield-check"></i> Rule Evaluation
        </div>
        <div class="decode-fields">
            <div class="decode-field"><span>Action:</span> <span style="color:${rulesMatched ? 'var(--color-red)' : 'var(--color-green)'}; font-weight:bold">${rulesMatched ? 'DROP (Block)' : 'FORWARD (Allow)'}</span></div>
            <div class="decode-field"><span>Hash Code:</span> <span>0x${(computeQuickHash(PACKET_PRESETS[state.selectedPresetKey]) >>> 0).toString(16).toUpperCase()}</span></div>
        </div>
    `;
    card.appendChild(lRules);

    lucide.createIcons();
}

// ==========================================
// 5. ANIMATED PIPELINE VISUALIZATION (SVG)
// ==========================================

const NODE_LAYOUTS = {
    // X, Y coordinate ranges for components based on workers count
    // Viewport is width=100% (treated as ~800px), height=450px
    leftMargin: 60,
    rightMargin: 740,
    topMargin: 40,
    bottomMargin: 410,
};

function generatePipelineNodes() {
    const w = 800; // Logical width
    const h = 450; // Logical height

    const nodes = {
        input: { id: 'input', label: 'pcap Input', sub: 'capture.pcap', x: 60, y: 225, type: 'file' },
        reader: { id: 'reader', label: 'ReaderThread', sub: 'Disk I/O', x: 180, y: 225, type: 'thread' },
        loadbalancer: { id: 'loadbalancer', label: 'LoadBalancer', sub: 'Hash & Route', x: 320, y: 225, type: 'thread' },
        workers: [], // Populated based on worker count
        writer: { id: 'writer', label: 'WriterThread', sub: 'pcap Write', x: 640, y: 225, type: 'thread' },
        output: { id: 'output', label: 'pcap Output', sub: 'filtered.pcap', x: 750, y: 150, type: 'file', color: 'var(--color-green)' },
        drop: { id: 'drop', label: 'Drop Bin', sub: 'Dropped Stats', x: 750, y: 300, type: 'drop', color: 'var(--color-red)' }
    };

    const N = state.workersCount;
    const workerX = 490;
    
    if (N === 1) {
        nodes.workers.push({ id: 'worker-0', label: 'Worker-0', sub: 'Parse/SNI/Rules', x: workerX, y: 225, type: 'worker', idx: 0 });
    } else {
        const startY = 80;
        const endY = 370;
        const step = (endY - startY) / (N - 1);
        for (let i = 0; i < N; i++) {
            nodes.workers.push({
                id: `worker-${i}`,
                label: `Worker-${i}`,
                sub: `Parser Queue`,
                x: workerX,
                y: startY + (i * step),
                type: 'worker',
                idx: i
            });
        }
    }

    return nodes;
}

function drawPipeline() {
    const svg = document.getElementById('pipeline-svg');
    const connGroup = document.getElementById('connections-group');
    const nodesGroup = document.getElementById('nodes-group');
    
    connGroup.innerHTML = "";
    nodesGroup.innerHTML = "";

    const nodes = generatePipelineNodes();
    
    // 1. Draw connections
    const drawPath = (from, to, color = "rgba(255, 255, 255, 0.08)", isActive = false) => {
        const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
        const dx = to.x - from.x;
        // Bezier curve control points
        const c1x = from.x + dx * 0.4;
        const c1y = from.y;
        const c2x = from.x + dx * 0.6;
        const c2y = to.y;
        
        path.setAttribute("d", `M ${from.x} ${from.y} C ${c1x} ${c1y}, ${c2x} ${c2y}, ${to.x} ${to.y}`);
        path.setAttribute("class", `connection-path ${isActive ? 'active' : ''}`);
        path.setAttribute("style", `stroke: ${color}`);
        connGroup.appendChild(path);
        return path;
    };

    // Connections: Input -> Reader -> LoadBalancer
    drawPath(nodes.input, nodes.reader, "var(--color-cyan)", true);
    drawPath(nodes.reader, nodes.loadbalancer, "var(--color-cyan)", true);

    // Connections: LoadBalancer -> Workers (and worker queues)
    nodes.workers.forEach(w => {
        // Draw the main path to worker queue
        const path = drawPath(nodes.loadbalancer, { x: w.x - 60, y: w.y }, "rgba(255, 255, 255, 0.15)");
        path.setAttribute("id", `path-lb-to-q-${w.idx}`);
        
        // Draw connection from queue exit to Worker thread
        drawPath({ x: w.x - 20, y: w.y }, w, "rgba(255, 255, 255, 0.2)");
        
        // Draw from Worker to Writer
        const wPath = drawPath(w, nodes.writer, "rgba(255, 255, 255, 0.15)");
        wPath.setAttribute("id", `path-worker-to-writer-${w.idx}`);
    });

    // Connections: Writer -> Output/Drop
    drawPath(nodes.writer, nodes.output, "rgba(16, 185, 129, 0.2)");
    drawPath(nodes.writer, nodes.drop, "rgba(244, 63, 94, 0.2)");

    // 2. Draw nodes
    const drawNodeEl = (n) => {
        const g = document.createElementNS("http://www.w3.org/2000/svg", "g");
        g.setAttribute("class", "node-group");
        g.setAttribute("id", `node-el-${n.id}`);
        g.setAttribute("transform", `translate(${n.x}, ${n.y})`);

        const c = document.createElementNS("http://www.w3.org/2000/svg", "circle");
        c.setAttribute("r", n.type === 'file' || n.type === 'drop' ? "26" : "28");
        
        let nodeClass = "node-circle";
        if (n.type === 'thread') nodeClass += " node-thread";
        if (n.type === 'worker') nodeClass += " node-thread node-orange";
        if (n.type === 'drop') nodeClass += " node-orange";
        
        c.setAttribute("class", nodeClass);
        if (n.color) {
            c.setAttribute("style", `stroke: ${n.color}`);
        }
        g.appendChild(c);

        // Sub icon representation
        let iconName = "file-text";
        if (n.type === 'thread' || n.type === 'worker') iconName = "cpu";
        if (n.type === 'drop') iconName = "trash-2";
        
        const iconContainer = document.createElementNS("http://www.w3.org/2000/svg", "g");
        iconContainer.setAttribute("transform", "translate(-10, -22)");
        
        const foreign = document.createElementNS("http://www.w3.org/2000/svg", "foreignObject");
        foreign.setAttribute("width", "20");
        foreign.setAttribute("height", "20");
        foreign.innerHTML = `<i data-lucide="${iconName}" style="width:16px;height:16px;color:rgba(255,255,255,0.4)"></i>`;
        iconContainer.appendChild(foreign);
        g.appendChild(iconContainer);

        // Texts
        const t1 = document.createElementNS("http://www.w3.org/2000/svg", "text");
        t1.setAttribute("class", "node-text");
        t1.setAttribute("y", "2");
        t1.textContent = n.label;
        g.appendChild(t1);

        const t2 = document.createElementNS("http://www.w3.org/2000/svg", "text");
        t2.setAttribute("class", "node-subtext");
        t2.setAttribute("y", "14");
        t2.textContent = n.sub;
        g.appendChild(t2);

        nodesGroup.appendChild(g);
    };

    // Draw non-worker nodes
    drawNodeEl(nodes.input);
    drawNodeEl(nodes.reader);
    drawNodeEl(nodes.loadbalancer);
    drawNodeEl(nodes.writer);
    drawNodeEl(nodes.output);
    drawNodeEl(nodes.drop);

    // Draw workers and their queue structures
    nodes.workers.forEach(w => {
        drawNodeEl(w);

        // Draw queue box
        const qg = document.createElementNS("http://www.w3.org/2000/svg", "g");
        qg.setAttribute("transform", `translate(${w.x - 65}, ${w.y - 12})`);
        qg.setAttribute("id", `queue-visual-box-${w.idx}`);

        // Queue Border
        const border = document.createElementNS("http://www.w3.org/2000/svg", "rect");
        border.setAttribute("width", "40");
        border.setAttribute("height", "24");
        border.setAttribute("class", "queue-bar-bg");
        qg.appendChild(border);

        // Queue segments (representing slots occupied)
        const barFill = document.createElementNS("http://www.w3.org/2000/svg", "rect");
        barFill.setAttribute("x", "2");
        barFill.setAttribute("y", "2");
        barFill.setAttribute("width", "0");
        barFill.setAttribute("height", "20");
        barFill.setAttribute("class", "queue-bar-fill normal");
        barFill.setAttribute("id", `queue-fill-${w.idx}`);
        qg.appendChild(barFill);

        // Queue capacity count text
        const qText = document.createElementNS("http://www.w3.org/2000/svg", "text");
        qText.setAttribute("x", "20");
        qText.setAttribute("y", "15");
        qText.setAttribute("class", "node-subtext");
        qText.setAttribute("style", "font-weight: 700; fill: #fff; font-size:9px; text-anchor: middle");
        qText.setAttribute("id", `queue-text-${w.idx}`);
        qText.textContent = "0";
        qg.appendChild(qText);

        nodesGroup.appendChild(qg);
    });

    lucide.createIcons();
}

// Spawns a visual packet flowing along the pipeline
function spawnVisualPacket(presetKey) {
    const bytes = PACKET_PRESETS[presetKey];
    const parsed = parsePacket(bytes);
    const hash = computeQuickHash(bytes);
    
    // Choose worker target index
    const targetWorkerIdx = Math.floorMod(hash, state.workersCount);
    
    let color = "var(--color-cyan)"; // Default Http
    let pTypeLabel = "HTTP";
    
    if (parsed.valid) {
        if (parsed.sni) {
            pTypeLabel = parsed.appType;
            if (pTypeLabel === 'YOUTUBE') color = '#ff0000';
            else if (pTypeLabel === 'FACEBOOK') color = '#1877f2';
            else if (pTypeLabel === 'GITHUB') color = '#a855f7';
            else if (pTypeLabel === 'TIKTOK') color = '#00f2fe';
            else if (pTypeLabel === 'INSTAGRAM') color = '#e1306c';
            else if (pTypeLabel === 'NETFLIX') color = '#e50914';
            else color = "var(--color-purple)"; // HTTPS TLS
        } else if (parsed.isUdp) {
            color = "var(--color-teal)";
            pTypeLabel = "DNS";
        }
    } else {
        if (presetKey === 'ipv6') {
            color = "var(--color-gray)";
            pTypeLabel = "IPv6";
        } else {
            color = "var(--color-red)";
            pTypeLabel = "MALF";
        }
    }

    const packetId = Math.random().toString(36).substring(2, 9);
    
    // Pipeline path milestones
    // 0: Reader Input -> Reader Thread
    // 1: Reader Thread -> Load Balancer
    // 2: Load Balancer -> Queue Entry -> Queue Processing
    // 3: Queue exit -> Worker Thread
    // 4: Worker Thread -> Writer Thread
    // 5: Writer Thread -> Output file / Drop Bin
    const packetObj = {
        id: packetId,
        bytes: bytes,
        parsed: parsed,
        targetWorker: targetWorkerIdx,
        stage: 0,
        t: 0, // Interpolation position on paths (0 to 1)
        x: 60,
        y: 225,
        color: color,
        label: pTypeLabel,
        isBlocked: shouldBlock(parsed)
    };

    state.activePackets.push(packetObj);
}

// Math helper
Math.floorMod = function(x, y) {
    return ((x % y) + y) % y;
};

// ==========================================
// 6. ENGINE SIMULATOR LOOP
// ==========================================

let lastTickTime = Date.now();
let spawnTimer = 0;

function runSimulationTick() {
    if (!state.isPlaying) return;

    const now = Date.now();
    const dt = ((now - lastTickTime) / 1000) * state.simSpeed;
    lastTickTime = now;

    // 1. Spawning simulated random/preset packet
    spawnTimer += dt;
    // Spawns a packet every 1.5 seconds average
    if (spawnTimer >= 1.2) {
        const randPreset = RANDOM_PRESETS[Math.floor(Math.random() * RANDOM_PRESETS.length)];
        spawnVisualPacket(randPreset);
        spawnTimer = 0;
    }

    // 2. Animate and update packet coordinates along paths
    const nodes = generatePipelineNodes();
    const packetsGroup = document.getElementById('packets-group');
    packetsGroup.innerHTML = "";

    const speedCoeff = 2.0; // Animation base speed

    // Temporary list of remaining packets
    const remainingPackets = [];

    state.activePackets.forEach(p => {
        let finishedStage = false;
        p.t += dt * speedCoeff;
        if (p.t >= 1.0) {
            p.t = 1.0;
            finishedStage = true;
        }

        // Current coordinates lookup based on stage
        let fromX = 0, fromY = 0, toX = 0, toY = 0;
        
        const wNode = nodes.workers[p.targetWorker];

        if (p.stage === 0) {
            // Input to Reader
            fromX = nodes.input.x; fromY = nodes.input.y;
            toX = nodes.reader.x; toY = nodes.reader.y;
        } else if (p.stage === 1) {
            // Reader to Load Balancer
            fromX = nodes.reader.x; fromY = nodes.reader.y;
            toX = nodes.loadbalancer.x; toY = nodes.loadbalancer.y;
        } else if (p.stage === 2) {
            // Load Balancer to Worker Queue Box (x-65, y)
            fromX = nodes.loadbalancer.x; fromY = nodes.loadbalancer.y;
            toX = wNode.x - 65; toY = wNode.y;
        } else if (p.stage === 3) {
            // Worker Queue processing (waiting inside queue, then parsing)
            // Simulates queue holding. We just keep packet at Queue position
            // until Worker pulls it.
            fromX = wNode.x - 65; fromY = wNode.y;
            toX = wNode.x; toY = wNode.y;
        } else if (p.stage === 4) {
            // Worker to Writer
            fromX = wNode.x; fromY = wNode.y;
            toX = nodes.writer.x; toY = nodes.writer.y;
        } else if (p.stage === 5) {
            // Writer to Output / Drop Bin
            fromX = nodes.writer.x; fromY = nodes.writer.y;
            if (p.isBlocked) {
                toX = nodes.drop.x; toY = nodes.drop.y;
            } else {
                toX = nodes.output.x; toY = nodes.output.y;
            }
        }

        // Interpolate (Cubic bezier curve mimic or straight lines)
        p.x = fromX + (toX - fromX) * p.t;
        p.y = fromY + (toY - fromY) * p.t;

        // Draw Packet Dot
        const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
        circle.setAttribute("cx", p.x);
        circle.setAttribute("cy", p.y);
        circle.setAttribute("r", "7");
        circle.setAttribute("class", "packet-dot");
        circle.setAttribute("fill", p.color);
        circle.setAttribute("style", `--packet-glow: ${p.color}`);
        packetsGroup.appendChild(circle);

        // Draw small label
        const txt = document.createElementNS("http://www.w3.org/2000/svg", "text");
        txt.setAttribute("x", p.x);
        txt.setAttribute("y", p.y - 10);
        txt.setAttribute("class", "node-subtext");
        txt.setAttribute("style", "font-weight:700; fill:#fff; font-size:7px; text-anchor:middle");
        txt.textContent = p.label;
        packetsGroup.appendChild(txt);

        // Handle stage completion transition rules
        if (finishedStage) {
            if (p.stage === 0) {
                p.stage = 1;
                p.t = 0;
                remainingPackets.push(p);
            } else if (p.stage === 1) {
                p.stage = 2;
                p.t = 0;
                // Add to worker queue state
                state.workerThreads[p.targetWorker].queue.push(p);
                remainingPackets.push(p);
            } else if (p.stage === 2) {
                // Now inside queue. Stop direct path animation. Let worker pick it up.
                p.stage = 3;
                p.t = 0;
                remainingPackets.push(p);
            } else if (p.stage === 3) {
                // Worker finished processing!
                p.stage = 4;
                p.t = 0;
                
                // Trigger worker flashing indicator in DOM
                flashWorkerNode(p.targetWorker);
                
                remainingPackets.push(p);
            } else if (p.stage === 4) {
                p.stage = 5;
                p.t = 0;
                remainingPackets.push(p);
            } else if (p.stage === 5) {
                // Packet reached destination! Update metrics counters.
                state.processedCount++;
                if (p.isBlocked) {
                    state.droppedCount++;
                } else {
                    state.allowedCount++;
                }
                
                // Track classification stats
                if (p.parsed.valid) {
                    state.appClassifier[p.parsed.appType]++;
                } else {
                    state.appClassifier.UNKNOWN++;
                }

                // Increment worker processed count
                state.workerThreads[p.targetWorker].processed++;
                
                updateStatsUI();
                // Packet removed from list (not pushed to remainingPackets)
            }
        } else {
            remainingPackets.push(p);
        }
    });

    // 3. Process worker queues (Workers pulling packets)
    state.workerThreads.forEach((worker, idx) => {
        if (worker.queue.length > 0 && !worker.active) {
            // Worker is free, pick next packet from queue
            const packet = worker.queue[0];
            
            // Set worker status to active
            worker.active = true;
            
            // Hold packet for a short duration representing computation time (e.g. 0.4s)
            setTimeout(() => {
                // Remove packet from queue
                worker.queue.shift();
                worker.active = false;
                
                // Let the packet advance to the Worker -> Writer stage
                const activePkt = state.activePackets.find(ap => ap.id === packet.id);
                if (activePkt && activePkt.stage === 3) {
                    activePkt.t = 1.0; // Mark stage 3 complete
                }
            }, 300 / state.simSpeed);
        }

        // Render queue fill indicator in SVG
        const fillBar = document.getElementById(`queue-fill-${idx}`);
        const textVal = document.getElementById(`queue-text-${idx}`);
        if (fillBar && textVal) {
            const size = worker.queue.length;
            const w = Math.min((size / 10) * 36, 36); // Max fill width 36px
            fillBar.setAttribute("width", w.toString());
            textVal.textContent = size;

            // Classes
            fillBar.removeAttribute("class");
            let warnClass = "normal";
            if (size > 7) warnClass = "danger";
            else if (size > 4) warnClass = "warning";
            fillBar.setAttribute("class", `queue-bar-fill ${warnClass}`);
        }
    });

    // Update active array
    state.activePackets = remainingPackets;

    // Simulate active throughput rate calculation
    state.throughputRate = state.isPlaying ? (1.5 * state.simSpeed) : 0;
    document.getElementById('stat-rate').innerText = state.throughputRate.toFixed(1) + " p/s";

    requestAnimationFrame(runSimulationTick);
}

function flashWorkerNode(workerIdx) {
    const el = document.getElementById(`node-el-worker-${workerIdx}`);
    if (el) {
        const circle = el.querySelector('.node-circle');
        circle.style.stroke = "var(--color-teal)";
        circle.style.strokeWidth = "4px";
        setTimeout(() => {
            circle.style.stroke = "var(--color-orange)";
            circle.style.strokeWidth = "2px";
        }, 150);
    }
}

// ==========================================
// 7. SETUP EVENT LISTENERS & INITS
// ==========================================

function setupEventListeners() {
    // Workers Slider
    const slider = document.getElementById('workers-slider');
    slider.addEventListener('input', (e) => {
        const count = parseInt(e.target.value);
        document.getElementById('workers-val').innerText = count;
        state.workersCount = count;
        
        // Reinitialize worker states
        initWorkerThreads(count);
        drawPipeline();
    });

    // Speed Slider
    const speedSlider = document.getElementById('speed-slider');
    speedSlider.addEventListener('input', (e) => {
        const val = parseFloat(e.target.value);
        state.simSpeed = val;
        
        let speedLabelText = "Normal";
        if (val < 0.6) speedLabelText = "Slow-mo";
        else if (val > 2.0) speedLabelText = "Hyper-speed";
        else if (val > 1.3) speedLabelText = "Fast";
        
        document.getElementById('speed-label').innerText = speedLabelText;
        document.getElementById('speed-badge').innerText = val.toFixed(1) + "x";
    });

    // Play/Pause Button
    const btnPlay = document.getElementById('btn-play-pause');
    btnPlay.addEventListener('click', () => {
        state.isPlaying = !state.isPlaying;
        
        const playIcon = document.getElementById('play-icon');
        const playText = document.getElementById('play-text');
        
        if (state.isPlaying) {
            btnPlay.className = "btn btn-primary btn-active";
            playIcon.setAttribute("data-lucide", "pause");
            playText.innerText = "Pause Simulation";
            lastTickTime = Date.now();
            requestAnimationFrame(runSimulationTick); // Resume the animation frame loop
        } else {
            btnPlay.className = "btn btn-primary";
            playIcon.setAttribute("data-lucide", "play");
            playText.innerText = "Start Simulation";
        }
        lucide.createIcons();
    });

    // Reset Button
    document.getElementById('btn-reset').addEventListener('click', () => {
        // Reset Stats
        state.processedCount = 0;
        state.allowedCount = 0;
        state.droppedCount = 0;
        state.throughputRate = 0;
        
        // Reset app counters
        for (const k in state.appClassifier) {
            state.appClassifier[k] = 0;
        }

        // Reset workers processed stats
        state.workerThreads.forEach(w => {
            w.processed = 0;
            w.queue = [];
            w.active = false;
        });

        state.activePackets = [];

        updateStatsUI();
        drawPipeline();
    });

    // Inject Random Button
    document.getElementById('btn-inject-random').addEventListener('click', () => {
        const randPreset = RANDOM_PRESETS[Math.floor(Math.random() * RANDOM_PRESETS.length)];
        spawnVisualPacket(randPreset);
        
        // Briefly animate the Inject button
        const btn = document.getElementById('btn-inject-random');
        btn.style.transform = "scale(0.95)";
        setTimeout(() => { btn.style.transform = "none"; }, 100);
    });

    // Preset packet change
    const presetSelect = document.getElementById('packet-presets');
    presetSelect.addEventListener('change', (e) => {
        state.selectedPresetKey = e.target.value;
        updateHexViewer(state.selectedPresetKey);
    });

    // Inject Preset Button
    document.getElementById('btn-inject-preset').addEventListener('click', () => {
        spawnVisualPacket(state.selectedPresetKey);
    });

    // Add Domain Rule
    document.getElementById('btn-add-domain').addEventListener('click', () => {
        const input = document.getElementById('rule-domain');
        const kw = input.value.trim().toLowerCase();
        if (kw) {
            state.blockedDomains.add(kw);
            input.value = "";
            renderActiveRules();
            updateHexViewer(state.selectedPresetKey); // Refresh evaluation on current preset
        }
    });

    // Add IP Rule
    document.getElementById('btn-add-ip').addEventListener('click', () => {
        const input = document.getElementById('rule-ip');
        const ip = input.value.trim();
        // Basic IP format validator
        if (/^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(ip)) {
            state.blockedIps.add(ip);
            input.value = "";
            renderActiveRules();
            updateHexViewer(state.selectedPresetKey);
        } else {
            alert("Invalid IP Address format. Use format: e.g. 192.168.1.1");
        }
    });

    // App Checkbox Rules
    document.querySelectorAll('.block-app-checkbox').forEach(cb => {
        cb.addEventListener('change', (e) => {
            const app = e.target.getAttribute('data-app');
            if (e.target.checked) {
                state.blockedApps.add(app);
            } else {
                state.blockedApps.delete(app);
            }
            renderActiveRules();
            updateHexViewer(state.selectedPresetKey);
        });
    });

    // Delete Active Rule delegation
    document.getElementById('active-rules').addEventListener('click', (e) => {
        const button = e.target.closest('.delete-rule');
        if (!button) return;

        const type = button.getAttribute('data-type');
        const val = button.getAttribute('data-value');

        if (type === 'app') {
            state.blockedApps.delete(val);
            // uncheck checkbox
            const cb = document.querySelector(`.block-app-checkbox[data-app="${val}"]`);
            if (cb) cb.checked = false;
        } else if (type === 'domain') {
            state.blockedDomains.delete(val);
        } else if (type === 'ip') {
            state.blockedIps.delete(val);
        }

        renderActiveRules();
        updateHexViewer(state.selectedPresetKey);
    });
}

function initWorkerThreads(count) {
    state.workerThreads = [];
    for (let i = 0; i < count; i++) {
        state.workerThreads.push({
            id: `worker-${i}`,
            processed: 0,
            queue: [],
            active: false
        });
    }
}

// Run initial configurations on load
window.addEventListener('DOMContentLoaded', () => {
    initWorkerThreads(state.workersCount);
    drawPipeline();
    setupEventListeners();
    updateHexViewer(state.selectedPresetKey);
    renderActiveRules();
    updateStatsUI();

    // Start rendering frame loop
    requestAnimationFrame(runSimulationTick);
});