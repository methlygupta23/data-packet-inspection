# Java DPI Engine

A multi-threaded Deep Packet Inspection (DPI) engine written in Java,
based on a packet-analysis design originally written in C++.

Reads `.pcap` capture files, identifies which website/app each
connection belongs to (even over encrypted HTTPS, using TLS SNI),
applies blocking rules, and writes the allowed traffic to a new
output `.pcap` file along with a summary report.

## How it works

The engine is a 4-stage pipeline, each stage running on its own thread(s):

```
ReaderThread --> LoadBalancerThread --> WorkerThread(s) --> WriterThread
 (disk I/O)      (hash + route)         (parse, SNI,         (write file,
                                          flow tracking,        track stats)
                                          rule checking)
```

Packets belonging to the same network connection are always routed to
the same worker thread (via consistent hashing of the five-tuple), so
a connection's traffic is always processed in order by one thread -
this guarantees correct blocking decisions even when a domain name is
only visible in the very first packet of a connection.

## Build & Run

```bash
javac *.java
java Main <input.pcap> [output.pcap] [options]
```

### Options

| Flag | Description |
|---|---|
| `--workers N` | Number of worker threads (default: 4) |
| `--block-app APP` | Block an app type, e.g. `YOUTUBE`. Repeatable. |
| `--block-domain TEXT` | Block domains containing this text. Repeatable. |
| `--block-ip IP` | Block a specific destination IP. Repeatable. |
| `--help` | Show usage |

### Example

```bash
java Main capture.pcap filtered.pcap --block-app YOUTUBE --block-domain facebook --workers 8
```

## Project structure

| File | Responsibility |
|---|---|
| `RawPacket.java` | Holds one packet's raw bytes + timestamp |
| `PcapReader.java` | Reads `.pcap` files packet by packet |
| `PcapWriter.java` | Writes packets to a new `.pcap` file |
| `ParsedPacket.java` | Holds decoded Ethernet/IP/TCP fields |
| `PacketParser.java` | Parses Ethernet -> IP -> TCP/UDP headers |
| `SniExtractor.java` | Extracts the domain name from a TLS Client Hello |
| `FiveTuple.java` | Identifies a connection (src/dst IP+port, protocol) |
| `Flow.java` | Tracks one connection's SNI, app type, block status |
| `FlowTracker.java` | Thread-safe map of all tracked flows |
| `AppType.java` | Enum of known app categories |
| `RuleManager.java` | Decides whether a flow should be blocked |
| `Packet.java` / `PoisonPill.java` | Pipeline wrapper + thread shutdown signal |
| `QuickFlowHash.java` | Fast five-tuple hash computed straight from raw bytes |
| `ReaderThread.java` | Pipeline stage: reads the input file |
| `LoadBalancerThread.java` | Pipeline stage: hashes & routes packets to workers |
| `WorkerThread.java` | Pipeline stage: parsing, SNI, rules |
| `WriterThread.java` | Pipeline stage: writes output, tracks stats |
| `ReportGenerator.java` | Prints the final summary report |
| `ArgParser.java` | Parses command-line arguments |
| `Main.java` | Wires the whole pipeline together |

## Known limitations

- Only IPv4 is supported (no IPv6)
- SNI extraction only works on standard TLS Client Hello (no GREASE/ESNI/ECH handling)
- Flow direction is not normalized - a flow is tracked from whichever
  side sends the first identifiable packet (works correctly for our
  use case since SNI only ever appears in the client's outgoing hello)