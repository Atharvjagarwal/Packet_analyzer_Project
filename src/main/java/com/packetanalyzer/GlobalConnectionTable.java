package com.packetanalyzer;

import java.util.Comparator;
import java.util.EnumMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;

public final class GlobalConnectionTable {
    public record GlobalStats(int activeConnections, long totalConnectionsSeen,
            Map<DpiTypes.AppType, Long> appDistribution, List<Map.Entry<String, Long>> topDomains) {
    }

    private final List<ConnectionTracker> trackers = new CopyOnWriteArrayList<>();

    public void registerTracker(ConnectionTracker tracker) {
        if (tracker == null) {
            throw new IllegalArgumentException("Tracker cannot be null");
        }
        trackers.add(tracker);
    }

    public GlobalStats getStats() {
        Set<DpiTypes.FiveTuple> seenConnections = new HashSet<>();
        Map<DpiTypes.AppType, Long> apps = new EnumMap<>(DpiTypes.AppType.class);
        Map<String, Long> domains = new java.util.HashMap<>();
        long totalSeen = 0;
        for (ConnectionTracker tracker : trackers) {
            totalSeen += tracker.getStats().totalConnectionsSeen();
            for (ConnectionTracker.Connection connection : tracker.getAllConnections()) {
                if (connection.state == DpiTypes.ConnectionState.CLOSED) {
                    continue;
                }
                if (!seenConnections.add(connection.tuple)) {
                    continue;
                }
                if (connection.appType != DpiTypes.AppType.UNKNOWN) {
                    apps.merge(connection.appType, 1L, Long::sum);
                }
                if (!connection.sni.isBlank()) {
                    domains.merge(connection.sni, 1L, Long::sum);
                }
            }
        }
        List<Map.Entry<String, Long>> topDomains = domains.entrySet().stream()
                .sorted(Map.Entry.<String, Long>comparingByValue(Comparator.reverseOrder())
                        .thenComparing(Map.Entry.comparingByKey()))
                .limit(10)
                .map(entry -> Map.entry(entry.getKey(), entry.getValue()))
                .toList();
        return new GlobalStats(seenConnections.size(), totalSeen, Map.copyOf(apps), topDomains);
    }

    public String generateReport() {
        GlobalStats stats = getStats();
        StringBuilder report = new StringBuilder();
        report.append("Connection Summary\n")
                .append("  Active connections: ").append(stats.activeConnections()).append('\n')
                .append("  Total connections seen: ").append(stats.totalConnectionsSeen()).append('\n')
                .append("Application Distribution\n");
        stats.appDistribution().entrySet().stream()
                .sorted(Map.Entry.comparingByKey())
                .forEach(entry -> report.append("  ")
                        .append(DpiTypes.appTypeToString(entry.getKey())).append(": ")
                        .append(entry.getValue()).append('\n'));
        report.append("Top Domains\n");
        stats.topDomains().forEach(entry -> report.append("  ")
                .append(entry.getKey()).append(": ").append(entry.getValue()).append('\n'));
        return report.toString();
    }
}
