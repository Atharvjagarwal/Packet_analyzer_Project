package com.packetanalyzer;

import java.util.Locale;

public final class DpiTypes {
    private DpiTypes() {
    }

    public enum AppType {
        UNKNOWN,
        HTTP,
        HTTPS,
        DNS,
        TLS,
        QUIC,
        GOOGLE,
        FACEBOOK,
        YOUTUBE,
        TWITTER,
        INSTAGRAM,
        NETFLIX,
        AMAZON,
        MICROSOFT,
        APPLE,
        WHATSAPP,
        TELEGRAM,
        TIKTOK,
        SPOTIFY,
        ZOOM,
        DISCORD,
        GITHUB,
        CLOUDFLARE
    }

    public enum PacketAction {
        FORWARD,
        DROP,
        INSPECT,
        LOG_ONLY
    }

    public enum ConnectionState {
        NEW,
        ESTABLISHED,
        CLASSIFIED,
        BLOCKED,
        CLOSED
    }

    public record FiveTuple(long srcIp, long dstIp, int srcPort, int dstPort, int protocol) {
        public FiveTuple reverse() {
            return new FiveTuple(dstIp, srcIp, dstPort, srcPort, protocol);
        }

        public static String formatIp(long ip) {
            return ((ip >>> 24) & 0xFF) + "."
                    + ((ip >>> 16) & 0xFF) + "."
                    + ((ip >>> 8) & 0xFF) + "."
                    + (ip & 0xFF);
        }

        @Override
        public String toString() {
            return formatIp(srcIp) + ":" + srcPort + " -> " + formatIp(dstIp) + ":" + dstPort + " (" + protocolName(protocol) + ")";
        }

        private static String protocolName(int protocol) {
            return switch (protocol) {
                case 6 -> "TCP";
                case 17 -> "UDP";
                default -> "?";
            };
        }
    }

    public static String appTypeToString(AppType type) {
        return switch (type) {
            case UNKNOWN -> "Unknown";
            case HTTP -> "HTTP";
            case HTTPS -> "HTTPS";
            case DNS -> "DNS";
            case TLS -> "TLS";
            case QUIC -> "QUIC";
            case GOOGLE -> "Google";
            case FACEBOOK -> "Facebook";
            case YOUTUBE -> "YouTube";
            case TWITTER -> "Twitter/X";
            case INSTAGRAM -> "Instagram";
            case NETFLIX -> "Netflix";
            case AMAZON -> "Amazon";
            case MICROSOFT -> "Microsoft";
            case APPLE -> "Apple";
            case WHATSAPP -> "WhatsApp";
            case TELEGRAM -> "Telegram";
            case TIKTOK -> "TikTok";
            case SPOTIFY -> "Spotify";
            case ZOOM -> "Zoom";
            case DISCORD -> "Discord";
            case GITHUB -> "GitHub";
            case CLOUDFLARE -> "Cloudflare";
        };
    }

    public static AppType sniToAppType(String sni) {
        if (sni == null || sni.isBlank()) {
            return AppType.UNKNOWN;
        }
        String lower = sni.toLowerCase(Locale.ROOT);

        if (lower.contains("google") || lower.contains("gstatic") || lower.contains("googleapis")
                || lower.contains("ggpht") || lower.contains("gvt1")) {
            return AppType.GOOGLE;
        }
        if (lower.contains("youtube") || lower.contains("ytimg") || lower.contains("youtu.be")
                || lower.contains("yt3.ggpht")) {
            return AppType.YOUTUBE;
        }
        if (lower.contains("facebook") || lower.contains("fbcdn") || lower.contains("fb.com")
                || lower.contains("fbsbx") || lower.contains("meta.com")) {
            return AppType.FACEBOOK;
        }
        if (lower.contains("instagram") || lower.contains("cdninstagram")) {
            return AppType.INSTAGRAM;
        }
        if (lower.contains("whatsapp") || lower.contains("wa.me")) {
            return AppType.WHATSAPP;
        }
        if (lower.contains("twitter") || lower.contains("twimg") || lower.contains("x.com")
                || lower.contains("t.co")) {
            return AppType.TWITTER;
        }
        if (lower.contains("netflix") || lower.contains("nflxvideo") || lower.contains("nflximg")) {
            return AppType.NETFLIX;
        }
        if (lower.contains("amazon") || lower.contains("amazonaws") || lower.contains("cloudfront")
                || lower.contains("aws")) {
            return AppType.AMAZON;
        }
        if (lower.contains("microsoft") || lower.contains("msn.com") || lower.contains("office")
                || lower.contains("azure") || lower.contains("live.com") || lower.contains("outlook")
                || lower.contains("bing")) {
            return AppType.MICROSOFT;
        }
        if (lower.contains("apple") || lower.contains("icloud") || lower.contains("mzstatic")
                || lower.contains("itunes")) {
            return AppType.APPLE;
        }
        if (lower.contains("telegram") || lower.contains("t.me")) {
            return AppType.TELEGRAM;
        }
        if (lower.contains("tiktok") || lower.contains("tiktokcdn") || lower.contains("musical.ly")
                || lower.contains("bytedance")) {
            return AppType.TIKTOK;
        }
        if (lower.contains("spotify") || lower.contains("scdn.co")) {
            return AppType.SPOTIFY;
        }
        if (lower.contains("zoom")) {
            return AppType.ZOOM;
        }
        if (lower.contains("discord") || lower.contains("discordapp")) {
            return AppType.DISCORD;
        }
        if (lower.contains("github") || lower.contains("githubusercontent")) {
            return AppType.GITHUB;
        }
        if (lower.contains("cloudflare") || lower.contains("cf-")) {
            return AppType.CLOUDFLARE;
        }
        return AppType.HTTPS;
    }

    public static final class PacketJob {
        public long packetId;
        public FiveTuple tuple;
        public byte[] data;
        public int ethOffset;
        public int ipOffset;
        public int transportOffset;
        public int payloadOffset;
        public int payloadLength;
        public int tcpFlags;
        public byte[] payloadData;
        public long tsSec;
        public long tsUsec;
    }

    public static final class Flow {
        public FiveTuple tuple;
        public AppType appType = AppType.UNKNOWN;
        public String sni = "";
        public long packets;
        public long bytes;
        public boolean blocked;
    }
}
