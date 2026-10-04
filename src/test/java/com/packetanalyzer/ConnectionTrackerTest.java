package com.packetanalyzer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import org.junit.jupiter.api.Test;

class ConnectionTrackerTest {
    @Test
    void tracksBidirectionalFlowStateClassificationAndCleanup() {
        ConnectionTracker tracker = new ConnectionTracker(0, 2);
        DpiTypes.FiveTuple outbound = new DpiTypes.FiveTuple(
                0xC0A80164L, 0x8EFAB9CEL, 54321, 443, 6);
        DpiTypes.FiveTuple inbound = outbound.reverse();

        ConnectionTracker.Connection connection = tracker.updateConnection(
                ConnectionTracker.canonical(outbound), 60, true, ConnectionTracker.TCP_SYN);
        tracker.updateConnection(ConnectionTracker.canonical(inbound), 60, false,
                ConnectionTracker.TCP_SYN | ConnectionTracker.TCP_ACK);
        tracker.classifyConnection(outbound, DpiTypes.AppType.GOOGLE, "www.google.com");
        assertEquals(1, tracker.getActiveCount());
        assertEquals(2, connection.totalPackets());
        assertEquals(DpiTypes.ConnectionState.CLASSIFIED, connection.state);
        assertTrue(connection.synSeen);
        assertTrue(connection.synAckSeen);
        assertEquals("www.google.com", connection.sni);

        tracker.updateConnection(outbound, 60, true, ConnectionTracker.TCP_FIN);
        assertEquals(DpiTypes.ConnectionState.CLASSIFIED, connection.state);
        tracker.updateConnection(outbound, 60, true, ConnectionTracker.TCP_ACK);
        assertEquals(DpiTypes.ConnectionState.CLOSED, connection.state);
        tracker.cleanupStale(Duration.ZERO);
        assertEquals(0, tracker.getActiveCount());
        assertEquals(1, tracker.getStats().totalConnectionsSeen());
    }
}
