# DPI Engine - Deep Packet Inspection System


This document explains **everything** about this project - from basic networking concepts to the complete code architecture. After reading this, you should understand exactly how packets flow through the system without needing to read the code.

---

## Table of Contents

1. [What is DPI?](#1-what-is-dpi)
2. [Networking Background](#2-networking-background)
3. [Project Overview](#3-project-overview)
4. [File Structure](#4-file-structure)
5. [The Journey of a Packet (Simple Version)](#5-the-journey-of-a-packet-simple-version)
6. [The Journey of a Packet (Multi-threaded Version)](#6-the-journey-of-a-packet-multi-threaded-version)
7. [Deep Dive: Each Component](#7-deep-dive-each-component)
8. [How SNI Extraction Works](#8-how-sni-extraction-works)
9. [How Blocking Works](#9-how-blocking-works)
10. [Building and Running](#10-building-and-running)
11. [Understanding the Output](#11-understanding-the-output)

---

## 1. What is DPI?

**Deep Packet Inspection (DPI)** is a technology used to examine the contents of network packets as they pass through a checkpoint. Unlike simple firewalls that only look at packet headers (source/destination IP), DPI looks *inside* the packet payload.

### Real-World Uses:
- **ISPs**: Throttle or block certain applications (e.g., BitTorrent)
- **Enterprises**: Block social media on office networks
- **Parental Controls**: Block inappropriate websites
- **Security**: Detect malware or intrusion attempts

### What Our DPI Engine Does:
```
User Traffic (PCAP) → [DPI Engine] → Filtered Traffic (PCAP)
                           ↓
                    - Identifies apps (YouTube, Facebook, etc.)
                    - Blocks based on rules
                    - Generates reports
```

---

## 2. Networking Background

### The Network Stack (Layers)

When you visit a website, data travels through multiple "layers":

```
┌─────────────────────────────────────────────────────────┐
│ Layer 7: Application    │ HTTP, TLS, DNS               │
├─────────────────────────────────────────────────────────┤
│ Layer 4: Transport      │ TCP (reliable), UDP (fast)   │
├─────────────────────────────────────────────────────────┤
│ Layer 3: Network        │ IP addresses (routing)       │
├─────────────────────────────────────────────────────────┤
│ Layer 2: Data Link      │ MAC addresses (local network)│
└─────────────────────────────────────────────────────────┘
```

### A Packet's Structure

Every network packet is like a **Russian nesting doll** - headers wrapped inside headers:

```
┌──────────────────────────────────────────────────────────────────┐
│ Ethernet Header (14 bytes)                                       │
│ ┌──────────────────────────────────────────────────────────────┐ │
│ │ IP Header (20 bytes)                                         │ │
│ │ ┌──────────────────────────────────────────────────────────┐ │ │
│ │ │ TCP Header (20 bytes)                                    │ │ │
│ │ │ ┌──────────────────────────────────────────────────────┐ │ │ │
│ │ │ │ Payload (Application Data)                           │ │ │ │
│ │ │ │ e.g., TLS Client Hello with SNI                      │ │ │ │
│ │ │ └──────────────────────────────────────────────────────┘ │ │ │
│ │ └──────────────────────────────────────────────────────────┘ │ │
│ └──────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

### The Five-Tuple

A **connection** (or "flow") is uniquely identified by 5 values:

| Field | Example | Purpose |
|-------|---------|---------|
| Source IP | 192.168.1.100 | Who is sending |
| Destination IP | 172.217.14.206 | Where it's going |
| Source Port | 54321 | Sender's application identifier |
| Destination Port | 443 | Service being accessed (443 = HTTPS) |
| Protocol | TCP (6) | TCP or UDP |

**Why is this important?** 
- All packets with the same 5-tuple belong to the same connection
- If we block one packet of a connection, we should block all of them
- This is how we "track" conversations between computers

### What is SNI?

**Server Name Indication (SNI)** is part of the TLS/HTTPS handshake. When you visit `https://www.youtube.com`:

1. Your browser sends a "Client Hello" message
2. This message includes the domain name in **plaintext** (not encrypted yet!)
3. The server uses this to know which certificate to send

```
TLS Client Hello:
├── Version: TLS 1.2
├── Random: [32 bytes]
├── Cipher Suites: [list]
└── Extensions:
    └── SNI Extension:
        └── Server Name: "www.youtube.com"  ← We extract THIS!
```

**This is one way DPI can identify HTTPS traffic**: when the ClientHello contains an inspectable SNI extension, its hostname can be visible even though application data is encrypted. SNI is not available in every connection.

---

## 3. Project Overview

### What This Project Does

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│ Wireshark   │     │ DPI Engine  │     │ Output      │
│ Capture     │ ──► │             │ ──► │ PCAP        │
│ (input.pcap)│     │ - Parse     │     │ (filtered)  │
└─────────────┘     │ - Classify  │     └─────────────┘
                    │ - Block     │
                    │ - Report    │
                    └─────────────┘
```

### Two Versions

| Version | File | Use Case |
|---------|------|----------|
| Simple (Single-threaded) | `PacketAnalyzer.java` | Learning, small captures |
| Multi-threaded | `DpiEngine.java` | Production, large captures |

---

## 4. File Structure

```text
packet-analyzer/
├── pom.xml
├── src/
│   ├── main/java/com/packetanalyzer/
│   │   ├── PcapReader.java           # PCAP file handling
│   │   ├── PacketParser.java          # Network protocol parsing
│   │   ├── SniExtractor.java          # TLS/HTTP/DNS inspection
│   │   ├── DpiTypes.java              # Data structures and application types
│   │   ├── RuleManager.java           # Blocking rules
│   │   ├── ConnectionTracker.java     # Flow tracking
│   │   ├── GlobalConnectionTable.java # Connection statistics
│   │   ├── ThreadSafeQueue.java       # Thread-safe bounded queue
│   │   ├── PacketAnalyzer.java       # Packet inspection CLI
│   │   ├── DpiEngine.java            # Multi-threaded DPI engine
│   │   └── TestPcapGenerator.java    # Creates test data
│   └── test/java/com/packetanalyzer/ # JUnit tests
├── test_dpi.pcap                     # Sample capture with various traffic
└── README.md                         # This file!
```

---
## 5. The Journey of a Packet (Simple Version)

Let's trace a single packet through `PacketAnalyzer.java`:

### Step 1: Read PCAP File

```java
try (PcapReader reader = new PcapReader("capture.pcap")) {
    // Read packets before leaving this block; the reader closes automatically.
}
```

**What happens:**
1. Open the file in binary mode
2. Read the 24-byte global header (magic number, version, etc.)
3. Verify it's a valid PCAP file

**PCAP File Format:**
```
┌────────────────────────────┐
│ Global Header (24 bytes)   │  ← Read once at start
├────────────────────────────┤
│ Packet Header (16 bytes)   │  ← Timestamp, length
│ Packet Data (variable)     │  ← Actual network bytes
├────────────────────────────┤
│ Packet Header (16 bytes)   │
│ Packet Data (variable)     │
├────────────────────────────┤
│ ... more packets ...       │
└────────────────────────────┘
```

### Step 2: Read Each Packet

```java
PcapReader.RawPacket raw = new PcapReader.RawPacket();
while (reader.readNextPacket(raw)) {
    // raw.data contains the packet bytes
    // raw.header contains timestamp and length
}
```

**What happens:**
1. Read 16-byte packet header
2. Read N bytes of packet data (N = header.incl_len)
3. Return false when no more packets

### Step 3: Parse Protocol Headers

```java
PacketParser.ParsedPacket parsed = new PacketParser.ParsedPacket();
boolean valid = PacketParser.parse(raw, parsed);
```

**What happens (in PacketParser.java):**

```
raw.data bytes:
[0-13]   Ethernet Header
[14-33]  IP Header  
[34-53]  TCP Header
[54+]    Payload

After parsing:
parsed.src_mac  = "00:11:22:33:44:55"
parsed.dest_mac = "aa:bb:cc:dd:ee:ff"
parsed.src_ip   = "192.168.1.100"
parsed.dest_ip  = "172.217.14.206"
parsed.src_port = 54321
parsed.dest_port = 443
parsed.protocol = 6 (TCP)
parsed.has_tcp  = true
```

**Parsing the Ethernet Header (14 bytes):**
```
Bytes 0-5:   Destination MAC
Bytes 6-11:  Source MAC
Bytes 12-13: EtherType (0x0800 = IPv4)
```

**Parsing the IP Header (20+ bytes):**
```
Byte 0:      Version (4 bits) + Header Length (4 bits)
Byte 8:      TTL (Time To Live)
Byte 9:      Protocol (6=TCP, 17=UDP)
Bytes 12-15: Source IP
Bytes 16-19: Destination IP
```

**Parsing the TCP Header (20+ bytes):**
```
Bytes 0-1:   Source Port
Bytes 2-3:   Destination Port
Bytes 4-7:   Sequence Number
Bytes 8-11:  Acknowledgment Number
Byte 12:     Data Offset (header length)
Byte 13:     Flags (SYN, ACK, FIN, etc.)
```

### Step 4: Create Five-Tuple and Look Up Flow

```java
DpiTypes.FiveTuple tuple = new DpiTypes.FiveTuple(
        parsed.srcIpValue,
        parsed.destIpValue,
        parsed.srcPort,
        parsed.destPort,
        parsed.protocol);
ConnectionTracker.Connection connection = tracker.getOrCreateConnection(tuple);
```

**What happens:**
- The flow table is a hash map: `FiveTuple → Flow`
- If this 5-tuple exists, we get the existing flow
- If not, a new flow is created
- All packets with the same 5-tuple share the same flow

### Step 5: Extract SNI (Deep Packet Inspection)

```java
// Inspect a TLS ClientHello payload when one is present.
Optional<String> sni = SniExtractor.extract(packet.payloadData);
if (sni.isPresent()) {
    String domain = sni.get();
    DpiTypes.AppType app = DpiTypes.sniToAppType(domain);
    tracker.classifyConnection(tuple, app, domain);
}
```

**What happens (in SniExtractor.java):**

1. **Check if it's a TLS Client Hello:**
   ```
   Byte 0: Content Type = 0x16 (Handshake) ✓
   Byte 5: Handshake Type = 0x01 (Client Hello) ✓
   ```

2. **Navigate to Extensions:**
   ```
   Skip: Version, Random, Session ID, Cipher Suites, Compression
   ```

3. **Find SNI Extension (type 0x0000):**
   ```
   Extension Type: 0x0000 (SNI)
   Extension Length: N
   SNI List Length: M
   SNI Type: 0x00 (hostname)
   SNI Length: L
   SNI Value: "www.youtube.com"  ← FOUND!
   ```

4. **Map SNI to App Type:**
   ```java
   DpiTypes.AppType app = DpiTypes.sniToAppType("www.youtube.com");
   if (app == DpiTypes.AppType.YOUTUBE) {
       System.out.println("YouTube traffic detected");
   }
   ```

### Step 6: Check Blocking Rules

```java
Optional<RuleManager.BlockReason> reason =
        rules.shouldBlock(tuple.srcIp(), tuple.dstPort(), flow.appType, flow.sni);
if (reason.isPresent()) {
    tracker.blockConnection(tuple);
}
```

**What happens:**
```java
Optional<RuleManager.BlockReason> reason =
        rules.shouldBlock(sourceIp, destinationPort, app, domain);
return reason.isPresent();
```

### Step 7: Forward or Drop

```java
if (job.drop) {
    droppedPackets.incrementAndGet();
} else {
    // The ordered writer emits the original packet to the output PCAP.
    forwardedPackets.incrementAndGet();
}
```

### Step 8: Generate Report

After processing all packets:
```java
Map<DpiTypes.AppType, Long> appStats = engine.getStats().classifications();
appStats.forEach((app, count) ->
        System.out.println(DpiTypes.appTypeToString(app) + ": " + count + " packets"));
```

---

## 6. The Journey of a Packet (Multi-threaded Version)

The multi-threaded version (`DpiEngine.java`) adds **parallelism** for high performance:

### Architecture Overview

```
                    ┌─────────────────┐
                    │  Reader Thread  │
                    │  (reads PCAP)   │
                    └────────┬────────┘
                             │
              ┌──────────────┴──────────────┐
              │      hash(5-tuple) % 2      │
              ▼                             ▼
    ┌─────────────────┐           ┌─────────────────┐
    │  LB0 Thread     │           │  LB1 Thread     │
    │  (Load Balancer)│           │  (Load Balancer)│
    └────────┬────────┘           └────────┬────────┘
             │                             │
      ┌──────┴──────┐               ┌──────┴──────┐
      │hash % 2     │               │hash % 2     │
      ▼             ▼               ▼             ▼
┌──────────┐ ┌──────────┐   ┌──────────┐ ┌──────────┐
│FP0 Thread│ │FP1 Thread│   │FP2 Thread│ │FP3 Thread│
│(Fast Path)│ │(Fast Path)│   │(Fast Path)│ │(Fast Path)│
└─────┬────┘ └─────┬────┘   └─────┬────┘ └─────┬────┘
      │            │              │            │
      └────────────┴──────────────┴────────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │   Output Queue        │
              └───────────┬───────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │  Output Writer Thread │
              │  (writes to PCAP)     │
              └───────────────────────┘
```

### Why This Design?

1. **Load Balancers (LBs):** Distribute work across FPs
2. **Fast Paths (FPs):** Do the actual DPI processing
3. **Consistent Hashing:** Same 5-tuple always goes to same FP

**Why consistent hashing matters:**
```
Connection: 192.168.1.100:54321 → 142.250.185.206:443

Packet 1 (SYN):         hash → FP2
Packet 2 (SYN-ACK):     hash → FP2  (same FP!)
Packet 3 (Client Hello): hash → FP2  (same FP!)
Packet 4 (Data):        hash → FP2  (same FP!)

All packets of this connection go to FP2.
FP2 can track the flow state correctly.
```

### Detailed Flow

#### Step 1: Reader Thread

```java
PcapReader.RawPacket raw = new PcapReader.RawPacket();
while (reader.readNextPacket(raw)) {
    PacketParser.ParsedPacket parsed = new PacketParser.ParsedPacket();
    boolean valid = PacketParser.parse(raw, parsed);
    DpiEngine.PacketJob job = createPacketJob(raw, valid ? parsed : null);
    loadBalancers.get(selectLoadBalancer(job)).input.put(job);
}
```

#### Step 2: Load Balancer Thread

```java
private void run() {
    try {
        DpiEngine.PacketJob job;
        while ((job = input.take()) != null) {
            int workerIndex = selectWorker(job);
            workers.get(workerIndex).input.put(job);
        }
    } catch (InterruptedException exception) {
        Thread.currentThread().interrupt();
        abortPipeline();
    }
}
```

#### Step 3: Fast Path Thread

```java
private void run() {
    try {
        DpiEngine.PacketJob job;
        while ((job = input.take()) != null) {
            processPacket(job);
            output.put(job);
        }
    } catch (InterruptedException exception) {
        Thread.currentThread().interrupt();
        abortPipeline();
    }
}
```

#### Step 4: Output Writer Thread

```java
// The writer consumes completed jobs in packet-ID order.
while ((job = nextCompletedJob()) != null) {
    if (!job.drop) {
        writePacket(output, job.raw, littleEndian);
    }
}
```

### Thread-Safe Queue

The magic that makes multi-threading work:

```java
public final class ThreadSafeQueue<T> {
    private final Queue<T> queue = new ArrayDeque<>();
    private final int capacity;
    private boolean closed;

    public synchronized void put(T item) throws InterruptedException {
        while (queue.size() >= capacity && !closed) {
            wait();
        }
        if (closed) {
            throw new IllegalStateException("Cannot enqueue into a closed queue");
        }
        queue.add(item);
        notifyAll();
    }

    public synchronized T take() throws InterruptedException {
        while (queue.isEmpty() && !closed) {
            wait();
        }
        T item = queue.poll();
        notifyAll();
        return item;
    }

    public synchronized void close() {
        closed = true;
        notifyAll();
    }
}
```

**How it works:**
- `put()`: Producer adds an item, waiting consumers are notified
- `take()`: Consumer waits until an item is available, then removes it
- `synchronized`: Ensures only one thread changes the queue at a time
- `wait()` / `notifyAll()`: Coordinate waiting producers and consumers without busy-waiting

---

## 7. Deep Dive: Each Component

### PcapReader.java

**Purpose:** Read network captures saved by Wireshark

**Key structures:**
```java
public static final class GlobalHeader {
    public int magicNumber;
    public short versionMajor;
    public short versionMinor;
    public int snaplen;
    public int network;
    public boolean littleEndian;
    public byte[] rawHeader;
}

public static final class PacketHeader {
    public long tsSec;
    public long tsUsec;
    public long inclLen;
    public long origLen;
}
```

**Key functions:**
- `new PcapReader(filename)`: Open PCAP and validate the header
- `readNextPacket(raw)`: Read next packet into buffer
- `close()`: Clean up

### PacketParser.java

**Purpose:** Extract protocol fields from raw bytes

**Key function:**
```java
PacketParser.ParsedPacket parsed = new PacketParser.ParsedPacket();
if (PacketParser.parse(raw, parsed)) {
    // Parsed fields include Ethernet, IPv4, TCP/UDP, and payload data.
}
```

**Important concepts:**

*Network Byte Order:* Network protocols use big-endian (most significant byte first). Java's parser reads these fields explicitly from bytes, independent of the computer's native byte order:
```java
// Read a big-endian unsigned 16-bit network field.
private static int readU16(byte[] data, int offset) {
    return ((data[offset] & 0xFF) << 8)
            | (data[offset + 1] & 0xFF);
}
```

### SniExtractor.java

**Purpose:** Extract domain names from TLS and HTTP

**For TLS (HTTPS):**
```java
Optional<String> SniExtractor.extract(byte[] payload)
```

**For HTTP:**
```java
Optional<String> SniExtractor.extractHttpHost(byte[] payload)
```

### DpiTypes.java

**Purpose:** Define data structures used throughout

**FiveTuple:**
```java
public record FiveTuple(long srcIp, long dstIp, int srcPort, int dstPort, int protocol) {
    public FiveTuple reverse() {
        return new FiveTuple(dstIp, srcIp, dstPort, srcPort, protocol);
    }
}
```

**AppType:**
```java
public enum AppType {
    UNKNOWN,
    HTTP,
    HTTPS,
    DNS,
    TLS,
    QUIC,
    GOOGLE,
    FACEBOOK,
    YOUTUBE,
    TWITTER,
    INSTAGRAM,
    NETFLIX,
    AMAZON,
    MICROSOFT,
    APPLE
    // Additional application types are defined in DpiTypes.
}
```

**sniToAppType function:**
```java
DpiTypes.AppType app = DpiTypes.sniToAppType(sni);
if (app == DpiTypes.AppType.YOUTUBE) {
    System.out.println("YouTube domain detected");
}
```

---

## 8. How SNI Extraction Works

### The TLS Handshake

When you visit `https://www.youtube.com`:

```
┌──────────┐                              ┌──────────┐
│  Browser │                              │  Server  │
└────┬─────┘                              └────┬─────┘
     │                                         │
     │ ──── Client Hello ─────────────────────►│
     │      (includes SNI: www.youtube.com)    │
     │                                         │
     │ ◄─── Server Hello ───────────────────── │
     │      (includes certificate)             │
     │                                         │
     │ ──── Key Exchange ─────────────────────►│
     │                                         │
     │ ◄═══ Encrypted Data ══════════════════► │
     │      (from here on, everything is       │
     │       encrypted - we can't see it)      │
```

**We can only extract SNI from the Client Hello!**

### TLS Client Hello Structure

```
Byte 0:     Content Type = 0x16 (Handshake)
Bytes 1-2:  Version = 0x0301 (TLS 1.0)
Bytes 3-4:  Record Length

-- Handshake Layer --
Byte 5:     Handshake Type = 0x01 (Client Hello)
Bytes 6-8:  Handshake Length

-- Client Hello Body --
Bytes 9-10:  Client Version
Bytes 11-42: Random (32 bytes)
Byte 43:     Session ID Length (N)
Bytes 44 to 44+N: Session ID
... Cipher Suites ...
... Compression Methods ...

-- Extensions --
Bytes X-X+1: Extensions Length
For each extension:
    Bytes: Extension Type (2)
    Bytes: Extension Length (2)
    Bytes: Extension Data

-- SNI Extension (Type 0x0000) --
Extension Type: 0x0000
Extension Length: L
  SNI List Length: M
  SNI Type: 0x00 (hostname)
  SNI Length: K
  SNI Value: "www.youtube.com" ← THE GOAL!
```

### Our Extraction Code (Simplified)

```java
Optional<String> sni = SniExtractor.extract(payload);
if (sni.isPresent()) {
    String host = sni.get();
    DpiTypes.AppType app = DpiTypes.sniToAppType(host);
    System.out.println(host + " -> " + DpiTypes.appTypeToString(app));
}
```

---

## 9. How Blocking Works

### Rule Types

| Rule Type | Example | What it Blocks |
|-----------|---------|----------------|
| IP | `192.168.1.50` | All traffic from this source |
| App | `YouTube` | All YouTube connections |
| Domain | `*.tiktok.com` | Domains matching the configured exact or wildcard pattern |

### The Blocking Flow

```
Packet arrives
      │
      ▼
┌─────────────────────────────────┐
│ Is source IP in blocked list?  │──Yes──► DROP
└───────────────┬─────────────────┘
                │No
                ▼
┌─────────────────────────────────┐
│ Is app type in blocked list?   │──Yes──► DROP
└───────────────┬─────────────────┘
                │No
                ▼
┌─────────────────────────────────┐
│ Does SNI match blocked domain? │──Yes──► DROP
└───────────────┬─────────────────┘
                │No
                ▼
            FORWARD
```

### Flow-Based Blocking

**Important:** We block at the *flow* level, not packet level.

```
Connection to YouTube:
  Packet 1 (SYN)           → No SNI yet, FORWARD
  Packet 2 (SYN-ACK)       → No SNI yet, FORWARD  
  Packet 3 (ACK)           → No SNI yet, FORWARD
  Packet 4 (Client Hello)  → SNI: www.youtube.com
                           → App: YOUTUBE (blocked!)
                           → Mark flow as BLOCKED
                           → DROP this packet
  Packet 5 (Data)          → Flow is BLOCKED → DROP
  Packet 6 (Data)          → Flow is BLOCKED → DROP
  ...all subsequent packets → DROP
```

**Why this approach?**
- We can't identify the app until we see the Client Hello
- Once identified, we block all future packets of that flow
- The connection will fail/timeout on the client

---

## 10. Building and Running

### Prerequisites

- JDK 25 or newer
- Apache Maven 3.8 or newer

### Build and test

Run from the project root:

```powershell
mvn clean verify
```

This compiles the Java sources, runs the JUnit tests, and creates `target\packet-analyzer-1.0.0.jar`.

### Running

**Packet analyzer:**

```powershell
java -jar target\packet-analyzer-1.0.0.jar output.pcap
java -jar target\packet-analyzer-1.0.0.jar output.pcap 100
```

**DPI engine:**

```powershell
java -cp target\packet-analyzer-1.0.0.jar com.packetanalyzer.DpiEngine input.pcap output.pcap `
    --block-app YouTube `
    --block-app TikTok `
    --block-ip 192.168.1.50 `
    --block-domain "*.facebook.com"
```

**Configure threads:**

```powershell
java -cp target\packet-analyzer-1.0.0.jar com.packetanalyzer.DpiEngine input.pcap output.pcap --lbs 4 --fps 4
# Creates 4 load balancer threads x 4 workers per balancer = 16 workers
```

### Creating Test Data

```powershell
java -cp target\packet-analyzer-1.0.0.jar com.packetanalyzer.TestPcapGenerator
```

This creates `generated_test.pcap` with synthetic TLS/SNI, HTTP, DNS, and blocked-source traffic. Provide an output path as the first argument to choose another location.

---
## 11. Understanding the Output

### Sample Output

```
╔══════════════════════════════════════════════════════════════╗
║              DPI ENGINE v2.0 (Multi-threaded)                 ║
╠══════════════════════════════════════════════════════════════╣
║ Load Balancers:  2    FPs per LB:  2    Total FPs:  4        ║
╚══════════════════════════════════════════════════════════════╝

[Rules] Blocked app: YouTube
[Rules] Blocked IP: 192.168.1.50

[Reader] Processing packets...
[Reader] Done reading 77 packets

╔══════════════════════════════════════════════════════════════╗
║                      PROCESSING REPORT                        ║
╠══════════════════════════════════════════════════════════════╣
║ Total Packets:                77                              ║
║ Total Bytes:                5738                              ║
║ TCP Packets:                  73                              ║
║ UDP Packets:                   4                              ║
╠══════════════════════════════════════════════════════════════╣
║ Forwarded:                    69                              ║
║ Dropped:                       8                              ║
╠══════════════════════════════════════════════════════════════╣
║ THREAD STATISTICS                                             ║
║   LB0 dispatched:             53                              ║
║   LB1 dispatched:             24                              ║
║   FP0 processed:              53                              ║
║   FP1 processed:               0                              ║
║   FP2 processed:               0                              ║
║   FP3 processed:              24                              ║
╠══════════════════════════════════════════════════════════════╣
║                   APPLICATION BREAKDOWN                       ║
╠══════════════════════════════════════════════════════════════╣
║ HTTPS                39  50.6% ##########                     ║
║ Unknown              16  20.8% ####                           ║
║ YouTube               4   5.2% # (BLOCKED)                    ║
║ DNS                   4   5.2% #                              ║
║ Facebook              3   3.9%                                ║
║ ...                                                           ║
╚══════════════════════════════════════════════════════════════╝

[Detected Domains/SNIs]
  - www.youtube.com -> YouTube
  - www.facebook.com -> Facebook
  - www.google.com -> Google
  - github.com -> GitHub
  ...
```

### What Each Section Means

| Section | Meaning |
|---------|---------|
| Configuration | Number of threads created |
| Rules | Which blocking rules are active |
| Total Packets | Packets read from input file |
| Forwarded | Packets written to output file |
| Dropped | Packets blocked (not written) |
| Thread Statistics | Work distribution across threads |
| Application Breakdown | Traffic classification results |
| Detected SNIs | Actual domain names found |

---

## 12. Extending the Project

### Ideas for Improvement

1. **Add More App Signatures**
   ```java
   DpiTypes.AppType app = DpiTypes.sniToAppType("www.twitch.tv");
   ```

2. **Add Bandwidth Throttling**
   ```java
   // A future throttling feature could delay packet processing.
   if (shouldThrottle(flow)) {
       Thread.sleep(10);
   }
   ```

3. **Add Live Statistics Dashboard**
   ```java
   // A future statistics task could periodically print a snapshot.
   Thread statsThread = new Thread(() -> {
       while (!Thread.currentThread().isInterrupted()) {
           printStats();
           try {
               Thread.sleep(1000);
           } catch (InterruptedException exception) {
               Thread.currentThread().interrupt();
           }
       }
   }, "stats-reporter");
   statsThread.start();
   ```

4. **Add QUIC/HTTP3 Support**
   - QUIC uses UDP on port 443
   - SNI is in the Initial packet (encrypted differently)

5. **Add Persistent Rules**
   - Save rules to file
   - Load on startup

---

## Summary

This DPI engine demonstrates:

1. **Network Protocol Parsing** - Understanding packet structure
2. **Deep Packet Inspection** - Looking inside encrypted connections
3. **Flow Tracking** - Managing stateful connections
4. **Multi-threaded Architecture** - Scaling with thread pools
5. **Producer-Consumer Pattern** - Thread-safe queues

The key insight is that a TLS ClientHello may expose the destination hostname through SNI, allowing the engine to classify some encrypted connections without decrypting their application data.

---

## Questions?

If you have questions about any part of this project, the Java code follows the same flow described in this document. Start with `PacketAnalyzer.java` to understand packet reading and parsing, then move to `DpiEngine.java` to see classification, filtering, and parallel processing.

Happy learning! 🚀