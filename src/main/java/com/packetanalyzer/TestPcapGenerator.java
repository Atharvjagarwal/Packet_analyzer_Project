package com.packetanalyzer;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Random;

public final class TestPcapGenerator {
    private static final String USER_MAC = "00:11:22:33:44:55";
    private static final String GATEWAY_MAC = "aa:bb:cc:dd:ee:ff";
    private static final String USER_IP = "192.168.1.100";
    private static final Random RANDOM = new Random(0x50434150L);

    private TestPcapGenerator() {
    }

    public static void main(String[] args) throws IOException {
        Path output = Path.of(args.length == 0 ? "generated_test.pcap" : args[0]);
        int sequenceBase = 1000;

        String[][] tlsConnections = {
                {"142.250.185.206", "www.google.com"},
                {"142.250.185.110", "www.youtube.com"},
                {"157.240.1.35", "www.facebook.com"},
                {"157.240.1.174", "www.instagram.com"},
                {"104.244.42.65", "twitter.com"},
                {"52.94.236.248", "www.amazon.com"},
                {"23.52.167.61", "www.netflix.com"},
                {"140.82.114.4", "github.com"},
                {"104.16.85.20", "discord.com"},
                {"35.186.224.25", "zoom.us"},
                {"35.186.227.140", "web.telegram.org"},
                {"99.86.0.100", "www.tiktok.com"},
                {"35.186.224.47", "open.spotify.com"},
                {"192.0.78.24", "www.cloudflare.com"},
                {"13.107.42.14", "www.microsoft.com"},
                {"17.253.144.10", "www.apple.com"}
        };
        String[][] httpConnections = {
                {"93.184.216.34", "example.com"},
                {"185.199.108.153", "httpbin.org"}
        };
        String[] dnsQueries = {
                "www.google.com", "www.youtube.com", "www.facebook.com", "api.twitter.com"
        };

        try (DataOutputStream outputStream = new DataOutputStream(Files.newOutputStream(output))) {
            writePcapHeader(outputStream);
            PacketWriter writer = new PacketWriter(outputStream);

            for (String[] connection : tlsConnections) {
                String destinationIp = connection[0];
                String sni = connection[1];
                int sourcePort = randomEphemeralPort();
                byte[] ethernet = ethernetHeader(USER_MAC, GATEWAY_MAC);
                byte[] tcp = tcpHeader(sourcePort, 443, sequenceBase, 0, 0x02);
                writer.writePacket(concat(ethernet, ipv4Header(USER_IP, destinationIp, 6, tcp.length), tcp));

                tcp = tcpHeader(443, sourcePort, sequenceBase + 1000L, sequenceBase + 1L, 0x12);
                writer.writePacket(concat(ethernetHeader(GATEWAY_MAC, USER_MAC),
                        ipv4Header(destinationIp, USER_IP, 6, tcp.length), tcp));

                tcp = tcpHeader(sourcePort, 443, sequenceBase + 1L, sequenceBase + 1001L, 0x10);
                writer.writePacket(concat(ethernet, ipv4Header(USER_IP, destinationIp, 6, tcp.length), tcp));

                byte[] tls = tlsClientHello(sni);
                tcp = tcpHeader(sourcePort, 443, sequenceBase + 1L, sequenceBase + 1001L, 0x18);
                writer.writePacket(concat(ethernet,
                        ipv4Header(USER_IP, destinationIp, 6, tcp.length + tls.length), tcp, tls));
                sequenceBase += 10000;
            }

            for (String[] connection : httpConnections) {
                int sourcePort = randomEphemeralPort();
                byte[] ethernet = ethernetHeader(USER_MAC, GATEWAY_MAC);
                byte[] tcp = tcpHeader(sourcePort, 80, sequenceBase, 0, 0x02);
                writer.writePacket(concat(ethernet,
                        ipv4Header(USER_IP, connection[0], 6, tcp.length), tcp));

                byte[] http = httpRequest(connection[1]);
                tcp = tcpHeader(sourcePort, 80, sequenceBase + 1L, 1, 0x18);
                writer.writePacket(concat(ethernet,
                        ipv4Header(USER_IP, connection[0], 6, tcp.length + http.length), tcp, http));
                sequenceBase += 10000;
            }

            for (String domain : dnsQueries) {
                int sourcePort = randomEphemeralPort();
                byte[] dns = dnsQuery(domain);
                byte[] udp = udpHeader(sourcePort, 53, dns.length);
                writer.writePacket(concat(ethernetHeader(USER_MAC, GATEWAY_MAC),
                        ipv4Header(USER_IP, "8.8.8.8", 17, udp.length + dns.length), udp, dns));
            }

            for (int i = 0; i < 5; i++) {
                int sourcePort = randomEphemeralPort();
                byte[] tcp = tcpHeader(sourcePort, 443, sequenceBase, 0, 0x02);
                writer.writePacket(concat(ethernetHeader("00:11:22:33:44:56", GATEWAY_MAC),
                        ipv4Header("192.168.1.50", "172.217.0.100", 6, tcp.length), tcp));
                sequenceBase += 1000;
            }
        }

        System.out.println("Created " + output + " with test traffic:");
        System.out.println("  - " + tlsConnections.length + " TLS connections with SNI");
        System.out.println("  - " + httpConnections.length + " HTTP connections");
        System.out.println("  - " + dnsQueries.length + " DNS queries");
        System.out.println("  - 5 packets from blocked IP 192.168.1.50");
    }

    private static void writePcapHeader(DataOutputStream output) throws IOException {
        writeLittleEndian32(output, 0xa1b2c3d4L);
        writeLittleEndian16(output, 2);
        writeLittleEndian16(output, 4);
        writeLittleEndian32(output, 0);
        writeLittleEndian32(output, 0);
        writeLittleEndian32(output, 65535);
        writeLittleEndian32(output, 1);
    }

    private static byte[] ethernetHeader(String sourceMac, String destinationMac) {
        ByteArrayOutputStream output = new ByteArrayOutputStream(14);
        output.writeBytes(macBytes(destinationMac));
        output.writeBytes(macBytes(sourceMac));
        writeBigEndian16(output, 0x0800);
        return output.toByteArray();
    }

    private static byte[] ipv4Header(String sourceIp, String destinationIp, int protocol, int payloadLength) {
        ByteArrayOutputStream output = new ByteArrayOutputStream(20);
        output.write(0x45);
        output.write(0);
        writeBigEndian16(output, 20 + payloadLength);
        writeBigEndian16(output, RANDOM.nextInt(1, 65536));
        writeBigEndian16(output, 0x4000);
        output.write(64);
        output.write(protocol);
        writeBigEndian16(output, 0);
        output.writeBytes(ipBytes(sourceIp));
        output.writeBytes(ipBytes(destinationIp));
        return output.toByteArray();
    }

    private static byte[] tcpHeader(int sourcePort, int destinationPort, long sequence,
                                    long acknowledgement, int flags) {
        ByteArrayOutputStream output = new ByteArrayOutputStream(20);
        writeBigEndian16(output, sourcePort);
        writeBigEndian16(output, destinationPort);
        writeBigEndian32(output, sequence);
        writeBigEndian32(output, acknowledgement);
        output.write(5 << 4);
        output.write(flags);
        writeBigEndian16(output, 65535);
        writeBigEndian16(output, 0);
        writeBigEndian16(output, 0);
        return output.toByteArray();
    }

    private static byte[] udpHeader(int sourcePort, int destinationPort, int payloadLength) {
        ByteArrayOutputStream output = new ByteArrayOutputStream(8);
        writeBigEndian16(output, sourcePort);
        writeBigEndian16(output, destinationPort);
        writeBigEndian16(output, 8 + payloadLength);
        writeBigEndian16(output, 0);
        return output.toByteArray();
    }

    private static byte[] tlsClientHello(String sni) {
        byte[] hostname = sni.getBytes(StandardCharsets.US_ASCII);
        ByteArrayOutputStream sniEntry = new ByteArrayOutputStream();
        sniEntry.write(0);
        writeBigEndian16(sniEntry, hostname.length);
        sniEntry.writeBytes(hostname);

        ByteArrayOutputStream sniData = new ByteArrayOutputStream();
        writeBigEndian16(sniData, sniEntry.size());
        sniData.writeBytes(sniEntry.toByteArray());

        ByteArrayOutputStream extensions = new ByteArrayOutputStream();
        writeBigEndian16(extensions, 0);
        writeBigEndian16(extensions, sniData.size());
        extensions.writeBytes(sniData.toByteArray());
        writeBigEndian16(extensions, 0x002b);
        writeBigEndian16(extensions, 3);
        extensions.write(2);
        writeBigEndian16(extensions, 0x0304);

        ByteArrayOutputStream body = new ByteArrayOutputStream();
        writeBigEndian16(body, 0x0303);
        byte[] randomBytes = new byte[32];
        RANDOM.nextBytes(randomBytes);
        body.writeBytes(randomBytes);
        body.write(0);
        writeBigEndian16(body, 4);
        writeBigEndian16(body, 0x1301);
        writeBigEndian16(body, 0x1302);
        body.write(1);
        body.write(0);
        writeBigEndian16(body, extensions.size());
        body.writeBytes(extensions.toByteArray());

        ByteArrayOutputStream handshake = new ByteArrayOutputStream();
        handshake.write(1);
        writeBigEndian24(handshake, body.size());
        handshake.writeBytes(body.toByteArray());

        ByteArrayOutputStream record = new ByteArrayOutputStream();
        record.write(0x16);
        writeBigEndian16(record, 0x0301);
        writeBigEndian16(record, handshake.size());
        record.writeBytes(handshake.toByteArray());
        return record.toByteArray();
    }

    private static byte[] httpRequest(String host) {
        return ("GET / HTTP/1.1\r\nHost: " + host
                + "\r\nUser-Agent: DPI-Test/1.0\r\nAccept: */*\r\n\r\n")
                .getBytes(StandardCharsets.US_ASCII);
    }

    private static byte[] dnsQuery(String domain) {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        writeBigEndian16(output, RANDOM.nextInt(1, 65536));
        writeBigEndian16(output, 0x0100);
        writeBigEndian16(output, 1);
        writeBigEndian16(output, 0);
        writeBigEndian16(output, 0);
        writeBigEndian16(output, 0);
        for (String label : domain.split("\\.")) {
            byte[] labelBytes = label.getBytes(StandardCharsets.US_ASCII);
            if (labelBytes.length > 63) {
                throw new IllegalArgumentException("DNS label exceeds 63 bytes: " + label);
            }
            output.write(labelBytes.length);
            output.writeBytes(labelBytes);
        }
        output.write(0);
        writeBigEndian16(output, 1);
        writeBigEndian16(output, 1);
        return output.toByteArray();
    }

    private static int randomEphemeralPort() {
        return RANDOM.nextInt(49152, 65536);
    }

    private static byte[] macBytes(String mac) {
        String[] octets = mac.split(":");
        if (octets.length != 6) {
            throw new IllegalArgumentException("Invalid MAC address: " + mac);
        }
        byte[] bytes = new byte[6];
        for (int i = 0; i < octets.length; i++) {
            bytes[i] = (byte) Integer.parseInt(octets[i], 16);
        }
        return bytes;
    }

    private static byte[] ipBytes(String ip) {
        String[] octets = ip.split("\\.");
        if (octets.length != 4) {
            throw new IllegalArgumentException("Invalid IPv4 address: " + ip);
        }
        byte[] bytes = new byte[4];
        for (int i = 0; i < octets.length; i++) {
            int value = Integer.parseInt(octets[i]);
            if (value < 0 || value > 255) {
                throw new IllegalArgumentException("Invalid IPv4 address: " + ip);
            }
            bytes[i] = (byte) value;
        }
        return bytes;
    }

    private static byte[] concat(byte[]... arrays) {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        for (byte[] array : arrays) {
            output.writeBytes(array);
        }
        return output.toByteArray();
    }

    private static void writeLittleEndian16(DataOutputStream output, int value) throws IOException {
        output.writeByte(value);
        output.writeByte(value >>> 8);
    }

    private static void writeLittleEndian32(DataOutputStream output, long value) throws IOException {
        for (int shift = 0; shift < 32; shift += 8) {
            output.writeByte((int) (value >>> shift));
        }
    }

    private static void writeBigEndian16(ByteArrayOutputStream output, int value) {
        output.write(value >>> 8);
        output.write(value);
    }

    private static void writeBigEndian24(ByteArrayOutputStream output, int value) {
        output.write(value >>> 16);
        output.write(value >>> 8);
        output.write(value);
    }

    private static void writeBigEndian32(ByteArrayOutputStream output, long value) {
        output.write((int) (value >>> 24));
        output.write((int) (value >>> 16));
        output.write((int) (value >>> 8));
        output.write((int) value);
    }

    private static final class PacketWriter {
        private final DataOutputStream output;
        private long timestamp = 1_700_000_000L;

        private PacketWriter(DataOutputStream output) {
            this.output = output;
        }

        private void writePacket(byte[] packet) throws IOException {
            writeLittleEndian32(output, timestamp++);
            writeLittleEndian32(output, RANDOM.nextInt(1_000_000));
            writeLittleEndian32(output, packet.length);
            writeLittleEndian32(output, packet.length);
            output.write(packet);
        }
    }
}
