package com.packetanalyzer;

import java.time.Duration;
import java.time.Instant;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;

public final class ConnectionTracker {
    public static final int TCP_FIN = 0x01;
    public static final int TCP_SYN = 0x02;
    public static final int TCP_RST = 0x04;
    public static final int TCP_ACK = 0x10;

    public static final class Connection {
        public final DpiTypes.FiveTuple tuple;
        public DpiTypes.ConnectionState state = DpiTypes.ConnectionState.NEW;
        public DpiTypes.AppType appType = DpiTypes.AppType.UNKNOWN;
        public String sni = "";
        public long packetsIn;
        public long packetsOut;
        public long bytesIn;
        public long bytesOut;
        public Instant firstSeen = Instant.now();
        public Instant lastSeen = firstSeen;
        public DpiTypes.PacketAction action = DpiTypes.PacketAction.FORWARD;
        public boolean synSeen;
        public boolean synAckSeen;
        public boolean finSeen;

        private Connection(DpiTypes.FiveTuple tuple) {
            this.tuple = tuple;
        }

        private Connection copy() {
            Connection copy = new Connection(tuple);
            copy.state = state;
            copy.appType = appType;
            copy.sni = sni;
            copy.packetsIn = packetsIn;
            copy.packetsOut = packetsOut;
            copy.bytesIn = bytesIn;
            copy.bytesOut = bytesOut;
            copy.firstSeen = firstSeen;
            copy.lastSeen = lastSeen;
            copy.action = action;
            copy.synSeen = synSeen;
            copy.synAckSeen = synAckSeen;
            copy.finSeen = finSeen;
            return copy;
        }

        public long totalPackets() {
            return packetsIn + packetsOut;
        }

        public long totalBytes() {
            return bytesIn + bytesOut;
        }
    }

    public record TrackerStats(int activeConnections, long totalConnectionsSeen,
            long classifiedConnections, long blockedConnections) {
    }

    private final int processorId;
    private final int maxConnections;
    private final Map<DpiTypes.FiveTuple, Connection> connections = new HashMap<>();
    private long totalSeen;
    private long classifiedCount;
    private long blockedCount;

    public ConnectionTracker(int processorId) {
        this(processorId, 100_000);
    }

    public ConnectionTracker(int processorId, int maxConnections) {
        if (maxConnections < 1) {
            throw new IllegalArgumentException("Maximum connections must be positive");
        }
        this.processorId = processorId;
        this.maxConnections = maxConnections;
    }

    public int getProcessorId() {
        return processorId;
    }

    public synchronized Connection getOrCreateConnection(DpiTypes.FiveTuple tuple) {
        DpiTypes.FiveTuple key = canonical(tuple);
        Connection connection = connections.get(key);
        if (connection == null) {
            if (connections.size() >= maxConnections) {
                evictOldest();
            }
            connection = new Connection(key);
            connections.put(key, connection);
            totalSeen++;
        }
        return connection;
    }

    public synchronized Connection updateConnection(DpiTypes.FiveTuple tuple, int packetSize,
            boolean outbound, int tcpFlags) {
        if (packetSize < 0) {
            throw new IllegalArgumentException("Packet size cannot be negative");
        }
        Connection connection = getOrCreateConnection(tuple);
        connection.lastSeen = Instant.now();
        if (outbound) {
            connection.packetsOut++;
            connection.bytesOut += packetSize;
        } else {
            connection.packetsIn++;
            connection.bytesIn += packetSize;
        }
        if (tuple.protocol() == 6) {
            updateTcpState(connection, tcpFlags);
        } else if (connection.state == DpiTypes.ConnectionState.NEW) {
            connection.state = DpiTypes.ConnectionState.ESTABLISHED;
        }
        return connection;
    }

    public synchronized void classifyConnection(DpiTypes.FiveTuple tuple,
            DpiTypes.AppType app, String domain) {
        Connection connection = getOrCreateConnection(tuple);
        if (app != null && app != DpiTypes.AppType.UNKNOWN) {
            if (connection.appType == DpiTypes.AppType.UNKNOWN) {
                classifiedCount++;
            }
            connection.appType = app;
            if (connection.state != DpiTypes.ConnectionState.BLOCKED
                    && connection.state != DpiTypes.ConnectionState.CLOSED) {
                connection.state = DpiTypes.ConnectionState.CLASSIFIED;
            }
        }
        if (domain != null && !domain.isBlank()) {
            connection.sni = domain;
        }
    }

    public synchronized void blockConnection(DpiTypes.FiveTuple tuple) {
        Connection connection = getOrCreateConnection(tuple);
        if (connection.action != DpiTypes.PacketAction.DROP) {
            blockedCount++;
        }
        connection.action = DpiTypes.PacketAction.DROP;
        connection.state = DpiTypes.ConnectionState.BLOCKED;
    }

    public synchronized void closeConnection(DpiTypes.FiveTuple tuple) {
        Connection connection = connections.get(canonical(tuple));
        if (connection != null) {
            connection.state = DpiTypes.ConnectionState.CLOSED;
        }
    }

    public synchronized Optional<Connection> findConnection(DpiTypes.FiveTuple tuple) {
        Connection connection = connections.get(canonical(tuple));
        return connection == null ? Optional.empty() : Optional.of(connection);
    }

    public synchronized List<Connection> getAllConnections() {
        return connections.values().stream().map(Connection::copy).toList();
    }

    public synchronized void forEach(Consumer<Connection> callback) {
        getAllConnections().forEach(callback);
    }

    public synchronized int getActiveCount() {
        return (int) connections.values().stream()
                .filter(connection -> connection.state != DpiTypes.ConnectionState.CLOSED)
                .count();
    }

    public synchronized TrackerStats getStats() {
        return new TrackerStats(getActiveCount(), totalSeen, classifiedCount, blockedCount);
    }

    public synchronized int cleanupStale(Duration timeout) {
        Instant cutoff = Instant.now().minus(timeout);
        List<DpiTypes.FiveTuple> stale = connections.values().stream()
                .filter(connection -> connection.state == DpiTypes.ConnectionState.CLOSED
                        || connection.lastSeen.isBefore(cutoff))
                .map(connection -> connection.tuple)
                .toList();
        stale.forEach(connections::remove);
        return stale.size();
    }

    public synchronized void clear() {
        connections.clear();
        totalSeen = 0;
        classifiedCount = 0;
        blockedCount = 0;
    }

    private void updateTcpState(Connection connection, int flags) {
        if ((flags & TCP_RST) != 0) {
            connection.state = DpiTypes.ConnectionState.CLOSED;
            return;
        }
        if ((flags & TCP_SYN) != 0) {
            if ((flags & TCP_ACK) != 0) {
                connection.synAckSeen = true;
            } else {
                connection.synSeen = true;
            }
        }
        if ((flags & TCP_FIN) != 0) {
            connection.finSeen = true;
        }
        if (connection.finSeen && (flags & TCP_ACK) != 0) {
            connection.state = DpiTypes.ConnectionState.CLOSED;
        } else if (connection.synSeen && connection.synAckSeen && (flags & TCP_ACK) != 0
                && connection.state == DpiTypes.ConnectionState.NEW) {
            connection.state = DpiTypes.ConnectionState.ESTABLISHED;
        }
    }

    private void evictOldest() {
        connections.values().stream()
                .min(Comparator.comparing(connection -> connection.lastSeen))
                .map(connection -> connection.tuple)
                .ifPresent(connections::remove);
    }

    public static DpiTypes.FiveTuple canonical(DpiTypes.FiveTuple tuple) {
        DpiTypes.FiveTuple reverse = tuple.reverse();
        return compare(tuple, reverse) <= 0 ? tuple : reverse;
    }

    private static int compare(DpiTypes.FiveTuple left, DpiTypes.FiveTuple right) {
        int result = Long.compareUnsigned(left.srcIp(), right.srcIp());
        if (result == 0) result = Long.compareUnsigned(left.dstIp(), right.dstIp());
        if (result == 0) result = Integer.compare(left.srcPort(), right.srcPort());
        if (result == 0) result = Integer.compare(left.dstPort(), right.dstPort());
        if (result == 0) result = Integer.compare(left.protocol(), right.protocol());
        return result;
    }
}
