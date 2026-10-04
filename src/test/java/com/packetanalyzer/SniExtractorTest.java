package com.packetanalyzer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SniExtractorTest {
    @TempDir
    Path tempDir;

    @Test
    void extractsTlsSniAndHttpHostFromGeneratedCapture() throws Exception {
        Path capture = tempDir.resolve("application-hosts.pcap");
        TestPcapGenerator.main(new String[] {capture.toString()});
        boolean foundTlsSni = false;
        boolean foundHttpHost = false;

        try (PcapReader reader = new PcapReader(capture.toString())) {
            PcapReader.RawPacket raw = new PcapReader.RawPacket();
            PacketParser.ParsedPacket parsed = new PacketParser.ParsedPacket();
            while (reader.readNextPacket(raw)) {
                assertTrue(PacketParser.parse(raw, parsed));
                if (!parsed.hasTcp || parsed.payloadLength == 0) {
                    continue;
                }
                if (parsed.destPort == 443
                        && SniExtractor.extract(parsed.payloadData).filter("www.google.com"::equals).isPresent()) {
                    foundTlsSni = true;
                }
                if (parsed.destPort == 80
                        && SniExtractor.extractHttpHost(parsed.payloadData)
                                .filter("example.com"::equals).isPresent()) {
                    foundHttpHost = true;
                }
            }
        }

        assertTrue(foundTlsSni, "Expected a TLS ClientHello with www.google.com SNI");
        assertTrue(foundHttpHost, "Expected an HTTP request with example.com Host header");
    }

    @Test
    void extractsDnsQuestionDomainAndRejectsMalformedCompressionPointer() throws Exception {
        Path capture = tempDir.resolve("dns-query.pcap");
        TestPcapGenerator.main(new String[] {capture.toString()});
        boolean foundQuery = false;

        try (PcapReader reader = new PcapReader(capture.toString())) {
            PcapReader.RawPacket raw = new PcapReader.RawPacket();
            PacketParser.ParsedPacket parsed = new PacketParser.ParsedPacket();
            while (reader.readNextPacket(raw)) {
                assertTrue(PacketParser.parse(raw, parsed));
                if (parsed.hasUdp && parsed.destPort == 53) {
                    assertTrue(SniExtractor.isDnsQuery(parsed.payloadData));
                    assertEquals("www.google.com",
                            SniExtractor.extractDnsQuery(parsed.payloadData).orElseThrow());
                    foundQuery = true;
                    break;
                }
            }
        }
        assertTrue(foundQuery);

        byte[] malformed = new byte[18];
        malformed[5] = 1;
        malformed[12] = (byte) 0xC0;
        assertTrue(SniExtractor.isDnsQuery(malformed));
        assertTrue(SniExtractor.extractDnsQuery(malformed).isEmpty());
        assertFalse(SniExtractor.isDnsQuery(null));
    }
}
