package com.packetanalyzer;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

public final class SniExtractor {
    private static final int CONTENT_TYPE_HANDSHAKE = 0x16;
    private static final int HANDSHAKE_CLIENT_HELLO = 0x01;
    private static final int EXTENSION_SNI = 0x0000;
    private static final int SNI_TYPE_HOSTNAME = 0x00;

    private SniExtractor() {
    }

    public static boolean isTlsClientHello(byte[] payload) {
        if (payload == null || payload.length < 9) {
            return false;
        }
        if ((payload[0] & 0xFF) != CONTENT_TYPE_HANDSHAKE) {
            return false;
        }
        int version = readU16(payload, 1);
        if (version < 0x0300 || version > 0x0304) {
            return false;
        }
        int recordLength = readU16(payload, 3);
        if (recordLength > payload.length - 5) {
            return false;
        }
        return (payload[5] & 0xFF) == HANDSHAKE_CLIENT_HELLO;
    }

    public static Optional<String> extract(byte[] payload) {
        if (payload == null || !isTlsClientHello(payload)) {
            return Optional.empty();
        }

        int offset = 5;
        int handshakeLength = readU24(payload, offset + 1);
        offset += 4;
        int handshakeEnd = offset + handshakeLength;
        int recordEnd = 5 + readU16(payload, 3);
        if (handshakeEnd > recordEnd || handshakeEnd > payload.length) {
            return Optional.empty();
        }
        offset += 2;
        offset += 32;

        if (offset >= handshakeEnd) {
            return Optional.empty();
        }
        int sessionIdLength = payload[offset] & 0xFF;
        offset += 1 + sessionIdLength;

        if (offset + 2 > handshakeEnd) {
            return Optional.empty();
        }
        int cipherSuitesLength = readU16(payload, offset);
        offset += 2 + cipherSuitesLength;

        if (offset >= handshakeEnd) {
            return Optional.empty();
        }
        int compressionMethodsLength = payload[offset] & 0xFF;
        offset += 1 + compressionMethodsLength;

        if (offset + 2 > handshakeEnd) {
            return Optional.empty();
        }
        int extensionsLength = readU16(payload, offset);
        offset += 2;
        int extensionsEnd = offset + extensionsLength;
        if (extensionsEnd > handshakeEnd) {
            extensionsEnd = handshakeEnd;
        }

        while (offset + 4 <= extensionsEnd) {
            int extensionType = readU16(payload, offset);
            int extensionLength = readU16(payload, offset + 2);
            offset += 4;
            if (offset + extensionLength > extensionsEnd) {
                break;
            }
            if (extensionType == EXTENSION_SNI) {
                if (extensionLength < 5) {
                    break;
                }
                int sniListLength = readU16(payload, offset);
                if (sniListLength < 3) {
                    break;
                }
                int sniType = payload[offset + 2] & 0xFF;
                int sniLength = readU16(payload, offset + 3);
                if (sniType != SNI_TYPE_HOSTNAME || sniLength > extensionLength - 5) {
                    break;
                }
                String sni = new String(payload, offset + 5, sniLength, StandardCharsets.US_ASCII);
                return Optional.of(sni);
            }
            offset += extensionLength;
        }
        return Optional.empty();
    }

    public static List<String> extractExtensions(byte[] payload) {
        List<String> extensions = new ArrayList<>();
        if (payload == null || !isTlsClientHello(payload)) {
            return extensions;
        }
        int offset = 5;
        int handshakeLength = readU24(payload, offset + 1);
        offset += 4;
        int handshakeEnd = offset + handshakeLength;
        int recordEnd = 5 + readU16(payload, 3);
        if (handshakeEnd > recordEnd || handshakeEnd > payload.length) {
            return extensions;
        }
        offset += 2;
        offset += 32;
        if (offset >= handshakeEnd) {
            return extensions;
        }
        int sessionIdLength = payload[offset] & 0xFF;
        offset += 1 + sessionIdLength;
        if (offset + 2 > handshakeEnd) {
            return extensions;
        }
        int cipherLength = readU16(payload, offset);
        offset += 2 + cipherLength;
        if (offset >= handshakeEnd) {
            return extensions;
        }
        int compressionLength = payload[offset] & 0xFF;
        offset += 1 + compressionLength;
        if (offset + 2 > handshakeEnd) {
            return extensions;
        }
        int extensionLength = readU16(payload, offset);
        offset += 2;
        int end = offset + extensionLength;
        if (end > handshakeEnd) {
            end = handshakeEnd;
        }
        while (offset + 4 <= end) {
            int type = readU16(payload, offset);
            int len = readU16(payload, offset + 2);
            offset += 4;
            if (offset + len > end) {
                break;
            }
            extensions.add("type=" + type + ",len=" + len);
            offset += len;
        }
        return extensions;
    }

    public static Optional<String> extractHttpHost(byte[] payload) {
        if (payload == null || payload.length < 4) {
            return Optional.empty();
        }
        String methods = new String(payload, 0, Math.min(payload.length, 4), StandardCharsets.US_ASCII);
        if (!(methods.startsWith("GET") || methods.startsWith("POST") || methods.startsWith("PUT")
                || methods.startsWith("HEAD") || methods.startsWith("PATCH") || methods.startsWith("DELETE")
                || methods.startsWith("OPTI"))) {
            return Optional.empty();
        }
        String text = new String(payload, StandardCharsets.US_ASCII);
        String lower = text.toLowerCase(Locale.ROOT);
        int index = lower.indexOf("host:");
        if (index < 0) {
            return Optional.empty();
        }
        int start = index + 5;
        while (start < text.length() && (text.charAt(start) == ' ' || text.charAt(start) == '\t')) {
            start++;
        }
        int end = start;
        while (end < text.length() && text.charAt(end) != '\r' && text.charAt(end) != '\n') {
            end++;
        }
        if (end <= start) {
            return Optional.empty();
        }
        String host = text.substring(start, end).trim();
        int colon = host.indexOf(':');
        if (colon >= 0) {
            host = host.substring(0, colon);
        }
        return Optional.of(host);
    }

    public static boolean isDnsQuery(byte[] payload) {
        return payload != null && payload.length >= 12
                && (payload[2] & 0x80) == 0 && readU16(payload, 4) > 0;
    }

    public static Optional<String> extractDnsQuery(byte[] payload) {
        if (!isDnsQuery(payload)) {
            return Optional.empty();
        }
        int offset = 12;
        StringBuilder domain = new StringBuilder();
        while (offset < payload.length) {
            int labelLength = payload[offset++] & 0xFF;
            if (labelLength == 0) {
                if (domain.isEmpty() || offset + 4 > payload.length) {
                    return Optional.empty();
                }
                return Optional.of(domain.toString());
            }
            if ((labelLength & 0xC0) != 0 || labelLength > 63 || offset + labelLength > payload.length
                    || domain.length() + labelLength + (domain.isEmpty() ? 0 : 1) > 253) {
                return Optional.empty();
            }
            if (!domain.isEmpty()) {
                domain.append('.');
            }
            domain.append(new String(payload, offset, labelLength, StandardCharsets.US_ASCII));
            offset += labelLength;
        }
        return Optional.empty();
    }

    public static boolean isQuicInitial(byte[] payload) {
        return payload != null && payload.length >= 5 && (payload[0] & 0x80) != 0;
    }

    public static Optional<String> extractQuicSni(byte[] payload) {
        if (!isQuicInitial(payload)) {
            return Optional.empty();
        }
        for (int handshakeOffset = 5; handshakeOffset < payload.length; handshakeOffset++) {
            if ((payload[handshakeOffset] & 0xFF) == HANDSHAKE_CLIENT_HELLO) {
                int recordOffset = handshakeOffset - 5;
                if (recordOffset < 0) {
                    continue;
                }
                Optional<String> sni = extract(java.util.Arrays.copyOfRange(payload, recordOffset, payload.length));
                if (sni.isPresent()) {
                    return sni;
                }
            }
        }
        return Optional.empty();
    }

    private static int readU16(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    }

    private static int readU24(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 16) | ((data[offset + 1] & 0xFF) << 8) | (data[offset + 2] & 0xFF);
    }
}
