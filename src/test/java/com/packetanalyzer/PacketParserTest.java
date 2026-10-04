package com.packetanalyzer;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.util.Arrays;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class PacketParserTest {
    @TempDir
    Path tempDir;

    @Test
    void clearsPreviousPacketFieldsAndIgnoresEthernetPadding() throws Exception {
        Path capture = tempDir.resolve("parser-input.pcap");
        TestPcapGenerator.main(new String[] {capture.toString()});
        PacketParser.ParsedPacket parsed = new PacketParser.ParsedPacket();
        boolean foundUdp = false;

        try (PcapReader reader = new PcapReader(capture.toString())) {
            PcapReader.RawPacket raw = new PcapReader.RawPacket();
            while (reader.readNextPacket(raw)) {
                if (foundUdp) {
                    break;
                }
                assertTrue(PacketParser.parse(raw, parsed));
                if (parsed.hasUdp) {
                    foundUdp = true;
                    assertFalse(parsed.hasTcp);
                    assertTrue(parsed.seqNumber == 0);
                }
            }
        }
        assertTrue(foundUdp);

        try (PcapReader reader = new PcapReader(capture.toString())) {
            PcapReader.RawPacket raw = new PcapReader.RawPacket();
            assertTrue(reader.readNextPacket(raw));
            raw.data = Arrays.copyOf(raw.data, raw.data.length + 8);
            assertTrue(PacketParser.parse(raw, parsed));
            assertTrue(parsed.payloadLength == 0);

            raw.data[16] = 0;
            raw.data[17] = 20;
            assertFalse(PacketParser.parse(raw, parsed));
        }
    }
}
