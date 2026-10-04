package com.packetanalyzer;

public final class PacketParser {
    public static final class ParsedPacket {
        public long timestampSec;
        public long timestampUsec;
        public String srcMac;
        public String destMac;
        public int etherType;
        public boolean hasIp;
        public int ipVersion;
        public String srcIp;
        public String destIp;
        public int protocol;
        public int ttl;
        public int fragmentOffset;
        public boolean moreFragments;
        public int packetEnd;
        public int payloadEnd;
        public long srcIpValue;
        public long destIpValue;
        public boolean hasTcp;
        public boolean hasUdp;
        public int srcPort;
        public int destPort;
        public int tcpFlags;
        public long seqNumber;
        public long ackNumber;
        public int payloadLength;
        public byte[] payloadData;

        private void reset(int packetLength) {
            timestampSec = 0;
            timestampUsec = 0;
            srcMac = null;
            destMac = null;
            etherType = 0;
            hasIp = false;
            ipVersion = 0;
            srcIp = null;
            destIp = null;
            protocol = 0;
            ttl = 0;
            fragmentOffset = 0;
            moreFragments = false;
            packetEnd = packetLength;
            payloadEnd = packetLength;
            srcIpValue = 0;
            destIpValue = 0;
            hasTcp = false;
            hasUdp = false;
            srcPort = 0;
            destPort = 0;
            tcpFlags = 0;
            seqNumber = 0;
            ackNumber = 0;
            payloadLength = 0;
            payloadData = new byte[0];
        }
    }

    public static boolean parse(PcapReader.RawPacket raw, ParsedPacket parsed) {
        if (raw == null || raw.header == null || raw.data == null || parsed == null) {
            return false;
        }
        parsed.reset(raw.data.length);
        parsed.timestampSec = raw.header.tsSec;
        parsed.timestampUsec = raw.header.tsUsec;
        byte[] data = raw.data;
        int[] offsetRef = new int[] {0};

        if (!parseEthernet(data, parsed, offsetRef)) {
            return false;
        }

        if (parsed.etherType == 0x0800) {
            if (!parseIpv4(data, parsed, offsetRef)) {
                return false;
            }
            if (parsed.fragmentOffset != 0) {
                offsetRef[0] = Math.min(parsed.packetEnd, data.length);
            } else if (parsed.protocol == 6) {
                if (!parseTcp(data, parsed, offsetRef)) {
                    return false;
                }
            } else if (parsed.protocol == 17) {
                if (!parseUdp(data, parsed, offsetRef)) {
                    return false;
                }
            }
        }

        int offset = offsetRef[0];
        int packetEnd = Math.min(Math.min(parsed.packetEnd, parsed.payloadEnd), data.length);
        if (offset < packetEnd) {
            parsed.payloadLength = packetEnd - offset;
            parsed.payloadData = java.util.Arrays.copyOfRange(data, offset, packetEnd);
        } else {
            parsed.payloadLength = 0;
            parsed.payloadData = new byte[0];
        }
        return true;
    }

    private static boolean parseEthernet(byte[] data, ParsedPacket parsed, int[] offsetRef) {
        if (data.length < 14) {
            return false;
        }
        parsed.destMac = macToString(data, 0, 6);
        parsed.srcMac = macToString(data, 6, 6);
        parsed.etherType = readU16(data, 12);
        offsetRef[0] = 14;
        return true;
    }

    private static boolean parseIpv4(byte[] data, ParsedPacket parsed, int[] offsetRef) {
        int offset = offsetRef[0];
        if (data.length < offset + 20) {
            return false;
        }
        int versionIhl = data[offset] & 0xFF;
        int version = (versionIhl >> 4) & 0x0F;
        if (version != 4) {
            return false;
        }
        int ihl = versionIhl & 0x0F;
        int headerLength = ihl * 4;
        if (headerLength < 20 || data.length < offset + headerLength) {
            return false;
        }
        int totalLength = readU16(data, offset + 2);
        if (totalLength < headerLength) {
            return false;
        }
        int fragmentField = readU16(data, offset + 6);
        int packetEnd = offset + totalLength;
        int ttl = data[offset + 8] & 0xFF;
        int protocol = data[offset + 9] & 0xFF;
        int srcIp = readU32(data, offset + 12);
        int dstIp = readU32(data, offset + 16);

        parsed.hasIp = true;
        parsed.ipVersion = 4;
        parsed.protocol = protocol;
        parsed.ttl = ttl;
        parsed.fragmentOffset = fragmentField & 0x1FFF;
        parsed.moreFragments = (fragmentField & 0x2000) != 0;
        parsed.packetEnd = Math.min(packetEnd, data.length);
        parsed.payloadEnd = parsed.packetEnd;
        parsed.srcIpValue = Integer.toUnsignedLong(srcIp);
        parsed.destIpValue = Integer.toUnsignedLong(dstIp);
        parsed.srcIp = ipToString(srcIp);
        parsed.destIp = ipToString(dstIp);
        offsetRef[0] = offset + headerLength;
        return true;
    }

    private static boolean parseTcp(byte[] data, ParsedPacket parsed, int[] offsetRef) {
        int offset = offsetRef[0];
        if (parsed.packetEnd < offset + 20) {
            return false;
        }
        int srcPort = readU16(data, offset);
        int destPort = readU16(data, offset + 2);
        long seqNumber = readU32L(data, offset + 4);
        long ackNumber = readU32L(data, offset + 8);
        int dataOffset = (data[offset + 12] >> 4) & 0x0F;
        int headerLength = dataOffset * 4;
        int flags = data[offset + 13] & 0xFF;
        if (headerLength < 20 || parsed.packetEnd < offset + headerLength) {
            return false;
        }
        parsed.hasTcp = true;
        parsed.srcPort = srcPort;
        parsed.destPort = destPort;
        parsed.seqNumber = seqNumber;
        parsed.ackNumber = ackNumber;
        parsed.tcpFlags = flags;
        offsetRef[0] = offset + headerLength;
        return true;
    }

    private static boolean parseUdp(byte[] data, ParsedPacket parsed, int[] offsetRef) {
        int offset = offsetRef[0];
        if (parsed.packetEnd < offset + 8) {
            return false;
        }
        int srcPort = readU16(data, offset);
        int destPort = readU16(data, offset + 2);
        int udpLength = readU16(data, offset + 4);
        if (udpLength < 8) {
            return false;
        }
        parsed.hasUdp = true;
        parsed.srcPort = srcPort;
        parsed.destPort = destPort;
        parsed.payloadEnd = Math.min(offset + udpLength, parsed.packetEnd);
        offsetRef[0] = offset + 8;
        return true;
    }

    public static String macToString(byte[] data, int offset, int length) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < length; i++) {
            if (i > 0) {
                sb.append(':');
            }
            sb.append(String.format("%02X", data[offset + i] & 0xFF));
        }
        return sb.toString();
    }

    public static String ipToString(int ip) {
        return ((ip >>> 24) & 0xFF) + "."
                + ((ip >>> 16) & 0xFF) + "."
                + ((ip >>> 8) & 0xFF) + "."
                + (ip & 0xFF);
    }

    public static String protocolToString(int protocol) {
        return switch (protocol) {
            case 1 -> "ICMP";
            case 6 -> "TCP";
            case 17 -> "UDP";
            default -> "Unknown(" + protocol + ")";
        };
    }

    public static String tcpFlagsToString(int flags) {
        StringBuilder result = new StringBuilder();
        if ((flags & 0x02) != 0) result.append("SYN ");
        if ((flags & 0x10) != 0) result.append("ACK ");
        if ((flags & 0x01) != 0) result.append("FIN ");
        if ((flags & 0x04) != 0) result.append("RST ");
        if ((flags & 0x08) != 0) result.append("PSH ");
        if ((flags & 0x20) != 0) result.append("URG ");
        String text = result.toString().trim();
        return text.isEmpty() ? "none" : text;
    }

    private static int readU16(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    }

    private static long readU32L(byte[] data, int offset) {
        long value = ((data[offset] & 0xFFL) << 24)
                | ((data[offset + 1] & 0xFFL) << 16)
                | ((data[offset + 2] & 0xFFL) << 8)
                | (data[offset + 3] & 0xFFL);
        return value;
    }

    private static int readU32(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 24)
                | ((data[offset + 1] & 0xFF) << 16)
                | ((data[offset + 2] & 0xFF) << 8)
                | (data[offset + 3] & 0xFF);
    }
}
