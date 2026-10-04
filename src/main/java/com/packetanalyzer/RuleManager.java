package com.packetanalyzer;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

public class RuleManager {
    public enum BlockType {
        IP, PORT, APP, DOMAIN
    }

    public record BlockReason(BlockType type, String detail) {
    }

    public record RuleStats(int blockedIps, int blockedApps, int blockedDomains, int blockedPorts) {
    }

    private final Set<Long> blockedIps = new LinkedHashSet<>();
    private final Set<DpiTypes.AppType> blockedApps = EnumSet.noneOf(DpiTypes.AppType.class);
    private final Set<String> blockedDomains = new LinkedHashSet<>();
    private final Set<String> domainPatterns = new LinkedHashSet<>();
    private final Set<Integer> blockedPorts = new LinkedHashSet<>();

    public synchronized void blockIP(String ip) {
        blockedIps.add(parseIpv4(ip));
    }

    public synchronized void unblockIP(String ip) {
        blockedIps.remove(parseIpv4(ip));
    }

    public synchronized void blockIP(long ip) {
        blockedIps.add(validateIpv4Value(ip));
    }

    public synchronized void unblockIP(long ip) {
        blockedIps.remove(validateIpv4Value(ip));
    }

    public synchronized boolean isIPBlocked(long ip) {
        return blockedIps.contains(validateIpv4Value(ip));
    }

    public synchronized List<String> getBlockedIPs() {
        return blockedIps.stream().sorted().map(DpiTypes.FiveTuple::formatIp).toList();
    }

    public synchronized void blockApp(DpiTypes.AppType app) {
        if (app == null || app == DpiTypes.AppType.UNKNOWN) {
            throw new IllegalArgumentException("A specific application type is required");
        }
        blockedApps.add(app);
    }

    public synchronized void blockApp(String app) {
        blockedApps.add(parseApp(app));
    }

    public synchronized void unblockApp(DpiTypes.AppType app) {
        blockedApps.remove(app);
    }

    public synchronized void unblockApp(String app) {
        blockedApps.remove(parseApp(app));
    }

    public synchronized boolean isAppBlocked(DpiTypes.AppType app) {
        return blockedApps.contains(app);
    }

    public synchronized List<DpiTypes.AppType> getBlockedApps() {
        return blockedApps.stream().sorted().toList();
    }

    public synchronized void blockDomain(String domain) {
        String normalized = normalizeDomainRule(domain);
        (normalized.contains("*") ? domainPatterns : blockedDomains).add(normalized);
    }

    public synchronized void unblockDomain(String domain) {
        String normalized = normalizeDomainRule(domain);
        if (normalized.contains("*")) {
            domainPatterns.remove(normalized);
        } else {
            blockedDomains.remove(normalized);
        }
    }

    public synchronized boolean isDomainBlocked(String domain) {
        if (domain == null || domain.isBlank()) {
            return false;
        }
        String normalized = normalizeDomain(domain);
        if (blockedDomains.contains(normalized)) {
            return true;
        }
        return domainPatterns.stream().anyMatch(pattern -> domainMatchesPattern(normalized, pattern));
    }

    public synchronized List<String> getBlockedDomains() {
        return java.util.stream.Stream.concat(blockedDomains.stream(), domainPatterns.stream()).sorted().toList();
    }

    public synchronized void blockPort(int port) {
        blockedPorts.add(validatePort(port));
    }

    public synchronized void unblockPort(int port) {
        blockedPorts.remove(validatePort(port));
    }

    public synchronized boolean isPortBlocked(int port) {
        return blockedPorts.contains(validatePort(port));
    }

    public synchronized List<Integer> getBlockedPorts() {
        return blockedPorts.stream().sorted().toList();
    }

    public synchronized Optional<BlockReason> shouldBlock(long sourceIp, int destinationPort,
            DpiTypes.AppType app, String domain) {
        if (blockedIps.contains(validateIpv4Value(sourceIp))) {
            return Optional.of(new BlockReason(BlockType.IP, DpiTypes.FiveTuple.formatIp(sourceIp)));
        }
        if (blockedPorts.contains(validatePort(destinationPort))) {
            return Optional.of(new BlockReason(BlockType.PORT, Integer.toString(destinationPort)));
        }
        if (blockedApps.contains(app)) {
            return Optional.of(new BlockReason(BlockType.APP, DpiTypes.appTypeToString(app)));
        }
        if (isDomainBlocked(domain)) {
            return Optional.of(new BlockReason(BlockType.DOMAIN, domain));
        }
        return Optional.empty();
    }

    public synchronized boolean isBlocked(long sourceIp, DpiTypes.AppType app, String domain) {
        return blockedIps.contains(validateIpv4Value(sourceIp))
                || blockedApps.contains(app)
                || isDomainBlocked(domain);
    }

    public synchronized RuleStats getStats() {
        return new RuleStats(blockedIps.size(), blockedApps.size(),
                blockedDomains.size() + domainPatterns.size(), blockedPorts.size());
    }

    public synchronized void clearAll() {
        blockedIps.clear();
        blockedApps.clear();
        blockedDomains.clear();
        domainPatterns.clear();
        blockedPorts.clear();
    }

    public synchronized boolean saveRules(String filename) throws IOException {
        List<String> lines = new ArrayList<>();
        appendSection(lines, "[BLOCKED_IPS]", getBlockedIPs());
        appendSection(lines, "[BLOCKED_APPS]",
                getBlockedApps().stream().map(DpiTypes::appTypeToString).toList());
        appendSection(lines, "[BLOCKED_DOMAINS]", getBlockedDomains());
        appendSection(lines, "[BLOCKED_PORTS]",
                getBlockedPorts().stream().map(String::valueOf).toList());
        Files.write(Path.of(filename), lines, StandardCharsets.UTF_8);
        return true;
    }

    public synchronized boolean loadRules(String filename) throws IOException {
        Path path = Path.of(filename);
        if (!Files.isRegularFile(path)) {
            return false;
        }

        RuleManager parsed = new RuleManager();
        String section = "";
        for (String rawLine : Files.readAllLines(path, StandardCharsets.UTF_8)) {
            String line = rawLine.trim();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            if (line.startsWith("[") && line.endsWith("]")) {
                section = line.toUpperCase(Locale.ROOT);
                continue;
            }
            switch (section) {
                case "[BLOCKED_IPS]" -> parsed.blockIP(line);
                case "[BLOCKED_APPS]" -> parsed.blockApp(line);
                case "[BLOCKED_DOMAINS]" -> parsed.blockDomain(line);
                case "[BLOCKED_PORTS]" -> parsed.blockPort(parseInteger(line, "port"));
                default -> throw new IOException("Rule found outside a recognized section: " + line);
            }
        }
        replaceWith(parsed);
        return true;
    }

    private void replaceWith(RuleManager source) {
        blockedIps.clear();
        blockedIps.addAll(source.blockedIps);
        blockedApps.clear();
        blockedApps.addAll(source.blockedApps);
        blockedDomains.clear();
        blockedDomains.addAll(source.blockedDomains);
        domainPatterns.clear();
        domainPatterns.addAll(source.domainPatterns);
        blockedPorts.clear();
        blockedPorts.addAll(source.blockedPorts);
    }

    private static void appendSection(List<String> lines, String section, List<String> values) {
        lines.add(section);
        lines.addAll(values);
        lines.add("");
    }

    private static boolean domainMatchesPattern(String domain, String pattern) {
        if (pattern.startsWith("*.")) {
            String suffix = pattern.substring(1);
            return domain.endsWith(suffix) || domain.equals(pattern.substring(2));
        }
        StringBuilder regex = new StringBuilder("^");
        String[] parts = pattern.split("\\*", -1);
        for (int i = 0; i < parts.length; i++) {
            regex.append(java.util.regex.Pattern.quote(parts[i]));
            if (i < parts.length - 1) {
                regex.append(".*");
            }
        }
        regex.append('$');
        return domain.matches(regex.toString());
    }

    private static String normalizeDomainRule(String domain) {
        if (domain == null || domain.isBlank()) {
            throw new IllegalArgumentException("Domain rule cannot be empty");
        }
        String normalized = domain.trim().toLowerCase(Locale.ROOT);
        if (normalized.startsWith("*.") && normalized.length() <= 2) {
            throw new IllegalArgumentException("Wildcard domain must include a suffix");
        }
        return normalized;
    }

    private static String normalizeDomain(String domain) {
        return domain.trim().toLowerCase(Locale.ROOT);
    }

    private static DpiTypes.AppType parseApp(String name) {
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException("Application name cannot be empty");
        }
        String normalized = name.trim().replace('-', '_').replace(' ', '_');
        for (DpiTypes.AppType app : DpiTypes.AppType.values()) {
            if (app.name().equalsIgnoreCase(normalized)
                    || DpiTypes.appTypeToString(app).equalsIgnoreCase(name.trim())) {
                if (app == DpiTypes.AppType.UNKNOWN) {
                    break;
                }
                return app;
            }
        }
        throw new IllegalArgumentException("Unknown application: " + name);
    }

    private static long parseIpv4(String ip) {
        String[] octets = ip.split("\\.", -1);
        if (octets.length != 4) {
            throw new IllegalArgumentException("Invalid IPv4 address: " + ip);
        }
        long value = 0;
        for (String octet : octets) {
            int part = parseInteger(octet, "IPv4 octet");
            if (part < 0 || part > 255) {
                throw new IllegalArgumentException("Invalid IPv4 address: " + ip);
            }
            value = (value << 8) | part;
        }
        return value;
    }

    private static long validateIpv4Value(long value) {
        if (value < 0 || value > 0xFFFFFFFFL) {
            throw new IllegalArgumentException("IPv4 address value is out of range: " + value);
        }
        return value;
    }

    private static int validatePort(int port) {
        if (port < 0 || port > 65535) {
            throw new IllegalArgumentException("Port must be between 0 and 65535: " + port);
        }
        return port;
    }

    private static int parseInteger(String value, String field) {
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException exception) {
            throw new IllegalArgumentException("Invalid " + field + ": " + value, exception);
        }
    }
}
