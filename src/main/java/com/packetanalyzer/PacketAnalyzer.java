package com.packetanalyzer;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Locale;

public class PacketAnalyzer {
    public static void main(String[] args) throws Exception {
        if (args.length == 1 && (args[0].equals("--help") || args[0].equals("-h"))) {
            printUsage();
            return;
        }
        if (args.length < 1) {
            printUsage();
            System.exit(2);
        }
        if (args.length > 2) {
            throw new IllegalArgumentException("Too many arguments. Use --help to see usage.");
        }

        String filename = args[0];
        int maxPackets = -1;
        if (args.length == 2) {
            try {
                maxPackets = Integer.parseInt(args[1]);
            } catch (NumberFormatException exception) {
                throw new IllegalArgumentException("max_packets must be a positive integer", exception);
            }
            if (maxPackets < 1) {
                throw new IllegalArgumentException("max_packets must be a positive integer");
            }
        }

        System.out.println("====================================");
        System.out.println("     Packet Analyzer v1.0");
        System.out.println("====================================\n");

        try (PcapReader reader = new PcapReader(filename)) {
            System.out.println("--- Reading packets ---");
            PcapReader.RawPacket raw = new PcapReader.RawPacket();
            PacketParser.ParsedPacket parsed = new PacketParser.ParsedPacket();
            int packetCount = 0;
            int parseErrors = 0;

            while (reader.readNextPacket(raw)) {
                packetCount++;
                if (PacketParser.parse(raw, parsed)) {
                    printPacketSummary(parsed, packetCount);
                } else {
                    System.err.println("Warning: Failed to parse packet #" + packetCount);
                    parseErrors++;
                }
                if (maxPackets > 0 && packetCount >= maxPackets) {
                    System.out.println("\n(Stopped after " + maxPackets + " packets)");
                    break;
                }
            }

            System.out.println("\n====================================");
            System.out.println("Summary:");
            System.out.println("  Total packets read:  " + packetCount);
            System.out.println("  Parse errors:        " + parseErrors);
            System.out.println("====================================");
        }
    }

    private static void printUsage() {
        System.out.println("Usage: PacketAnalyzer <pcap_file> [max_packets]");
        System.out.println("\nArguments:");
        System.out.println("  pcap_file   - Path to a .pcap file captured by Wireshark");
        System.out.println("  max_packets - (Optional) Maximum number of packets to display");
        System.out.println("  --help      - Show this help message");
    }

    private static void printPacketSummary(PacketParser.ParsedPacket pkt, int packetNum) {
        long epochSeconds = pkt.timestampSec;
        Instant instant = Instant.ofEpochSecond(epochSeconds);
        String timeString = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
                .withZone(ZoneId.systemDefault())
                .format(instant) + "." + String.format(Locale.US, "%06d", pkt.timestampUsec);

        System.out.println("\n========== Packet #" + packetNum + " ==========");
        System.out.println("Time: " + timeString);
        System.out.println("\n[Ethernet]");
        System.out.println("  Source MAC:      " + pkt.srcMac);
        System.out.println("  Destination MAC: " + pkt.destMac);
        System.out.println("  EtherType:       0x" + String.format("%04X", pkt.etherType) + (pkt.etherType == 0x0800 ? " (IPv4)" : pkt.etherType == 0x86DD ? " (IPv6)" : pkt.etherType == 0x0806 ? " (ARP)" : ""));

        if (pkt.hasIp) {
            System.out.println("\n[IPv" + pkt.ipVersion + "]");
            System.out.println("  Source IP:      " + pkt.srcIp);
            System.out.println("  Destination IP: " + pkt.destIp);
            System.out.println("  Protocol:       " + PacketParser.protocolToString(pkt.protocol));
            System.out.println("  TTL:            " + pkt.ttl);
        }

        if (pkt.hasTcp) {
            System.out.println("\n[TCP]");
            System.out.println("  Source Port:      " + pkt.srcPort);
            System.out.println("  Destination Port: " + pkt.destPort);
            System.out.println("  Sequence Number:  " + pkt.seqNumber);
            System.out.println("  Ack Number:       " + pkt.ackNumber);
            System.out.println("  Flags:            " + PacketParser.tcpFlagsToString(pkt.tcpFlags));
        }

        if (pkt.hasUdp) {
            System.out.println("\n[UDP]");
            System.out.println("  Source Port:      " + pkt.srcPort);
            System.out.println("  Destination Port: " + pkt.destPort);
        }

        if (pkt.payloadLength > 0) {
            System.out.println("\n[Payload]");
            System.out.println("  Length: " + pkt.payloadLength + " bytes");
            System.out.print("  Preview: ");
            int previewLen = Math.min(pkt.payloadLength, 32);
            for (int i = 0; i < previewLen; i++) {
                System.out.print(String.format("%02X ", pkt.payloadData[i] & 0xFF));
            }
            if (pkt.payloadLength > 32) {
                System.out.print("...");
            }
            System.out.println();
        }
    }
}
