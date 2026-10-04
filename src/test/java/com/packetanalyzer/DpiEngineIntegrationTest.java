package com.packetanalyzer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.nio.file.Files;
import java.io.IOException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class DpiEngineIntegrationTest {
    @TempDir
    Path tempDir;

    @Test
    void runsThreadedPipelineBlocksTrafficAndWritesReadableCapture() throws Exception {
        Path input = tempDir.resolve("input.pcap");
        Path output = tempDir.resolve("filtered.pcap");
        TestPcapGenerator.main(new String[] {input.toString()});

        DpiEngine.Config config = new DpiEngine.Config();
        config.numLoadBalancers = 2;
        config.fpsPerLb = 2;
        config.queueSize = 2;
        DpiEngine engine = new DpiEngine(config);
        engine.blockIP("192.168.1.50");
        engine.blockApp("YouTube");
        engine.blockPort(53);
        engine.blockDomain("*.facebook.com");
        engine.processFile(input.toString(), output.toString());

        DpiEngine.EngineStats stats = engine.getStats();
        assertEquals(77, stats.totalPackets());
        assertEquals(11, stats.droppedPackets());
        assertEquals(66, stats.forwardedPackets());
        assertEquals(27, stats.activeConnections());
        assertTrue(stats.classifications().containsKey(DpiTypes.AppType.YOUTUBE));
        assertTrue(engine.generateClassificationReport().contains("Top Domains"));
        String processorReport = engine.generateReport();
        for (int processor = 0; processor < 4; processor++) {
            assertTrue(processorReport.matches("(?s).*FP " + processor + ": processed [1-9][0-9]*.*"),
                    "Expected processor " + processor + " to receive packets");
        }

        int outputPackets = 0;
        try (PcapReader reader = new PcapReader(output.toString())) {
            PcapReader.RawPacket packet = new PcapReader.RawPacket();
            PacketParser.ParsedPacket parsed = new PacketParser.ParsedPacket();
            while (reader.readNextPacket(packet)) {
                assertTrue(PacketParser.parse(packet, parsed));
                outputPackets++;
            }
        }
        assertEquals(66, outputPackets);
    }

    @Test
    void loadsConfiguredRulesAndSupportsAsyncLifecycle() throws Exception {
        Path input = tempDir.resolve("async-input.pcap");
        Path output = tempDir.resolve("async-filtered.pcap");
        Path rulesFile = tempDir.resolve("rules.conf");
        TestPcapGenerator.main(new String[] {input.toString()});
        RuleManager rules = new RuleManager();
        rules.blockPort(53);
        rules.saveRules(rulesFile.toString());

        DpiEngine.Config config = new DpiEngine.Config();
        config.rulesFile = rulesFile.toString();
        config.numLoadBalancers = 1;
        config.fpsPerLb = 1;
        config.queueSize = 1;
        DpiEngine engine = new DpiEngine(config);
        engine.start(input.toString(), output.toString());
        engine.waitForCompletion();

        assertEquals(77, engine.getStats().totalPackets());
        assertEquals(4, engine.getStats().droppedPackets());
        assertEquals(73, engine.getStats().forwardedPackets());
        assertTrue(engine.generateReport().contains("per-FP"));
    }

    @Test
    void outputFailureDoesNotLeavePartialCaptureOrWorkerThreads() throws Exception {
        Path input = tempDir.resolve("failure-input.pcap");
        Path outputDirectory = tempDir.resolve("output-directory");
        TestPcapGenerator.main(new String[] {input.toString()});
        Files.createDirectory(outputDirectory);

        DpiEngine engine = new DpiEngine();
        org.junit.jupiter.api.Assertions.assertThrows(IOException.class,
                () -> engine.processFile(input.toString(), outputDirectory.toString()));
        assertTrue(Files.isDirectory(outputDirectory));
        try (var files = Files.list(tempDir)) {
            assertTrue(files.noneMatch(path -> path.getFileName().toString()
                    .startsWith(".output-directory.")));
        }
        assertTrue(!engine.isRunning());
    }

    @Test
    void blocksDnsQueriesByQueriedDomain() throws Exception {
        Path input = tempDir.resolve("dns-input.pcap");
        Path output = tempDir.resolve("dns-filtered.pcap");
        TestPcapGenerator.main(new String[] {input.toString()});

        DpiEngine engine = new DpiEngine();
        engine.blockDomain("www.google.com");
        engine.processFile(input.toString(), output.toString());

        assertEquals(2, engine.getStats().droppedPackets());
        assertEquals(75, engine.getStats().forwardedPackets());
    }
}
