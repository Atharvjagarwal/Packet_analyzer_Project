package com.packetanalyzer;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class RuleManagerTest {
    @TempDir
    Path tempDir;

    @Test
    void appliesIpAppWildcardDomainAndPortRulesAndPersistsThem() throws Exception {
        RuleManager rules = new RuleManager();
        rules.blockIP("192.168.1.50");
        rules.blockApp("YouTube");
        rules.blockDomain("*.example.com");
        rules.blockPort(443);

        assertTrue(rules.isIPBlocked(0xC0A80132L));
        assertTrue(rules.isAppBlocked(DpiTypes.AppType.YOUTUBE));
        assertTrue(rules.isDomainBlocked("example.com"));
        assertTrue(rules.isDomainBlocked("video.example.com"));
        assertTrue(rules.isPortBlocked(443));
        assertFalse(rules.isDomainBlocked("notexample.com"));
        assertFalse(rules.isDomainBlocked("other.test"));

        Path rulesFile = tempDir.resolve("rules.conf");
        rules.saveRules(rulesFile.toString());
        RuleManager loaded = new RuleManager();
        assertTrue(loaded.loadRules(rulesFile.toString()));
        assertTrue(loaded.isIPBlocked(0xC0A80132L));
        assertTrue(loaded.isAppBlocked(DpiTypes.AppType.YOUTUBE));
        assertTrue(loaded.isDomainBlocked("api.example.com"));
        assertTrue(loaded.isPortBlocked(443));

        loaded.unblockIP("192.168.1.50");
        loaded.unblockApp("YouTube");
        loaded.unblockDomain("*.example.com");
        loaded.unblockPort(443);
        assertFalse(loaded.isIPBlocked(0xC0A80132L));
        assertFalse(loaded.isAppBlocked(DpiTypes.AppType.YOUTUBE));
        assertFalse(loaded.isDomainBlocked("api.example.com"));
        assertFalse(loaded.isPortBlocked(443));
    }
}
