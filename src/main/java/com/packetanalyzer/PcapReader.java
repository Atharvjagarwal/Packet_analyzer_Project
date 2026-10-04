package com.packetanalyzer;

import java.io.BufferedInputStream;
import java.io.Closeable;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class PcapReader implements Closeable {
    private static final long PCAP_MAGIC_NATIVE = 0xA1B2C3D4L;
    private static final long PCAP_MAGIC_SWAPPED = 0xD4C3B2A1L;

    private final InputStream inputStream;
    private boolean open;
    private boolean littleEndianFile;
    private int versionMajor;
    private int versionMinor;
    private int thisZone;
    private int sigfigs;
    private int snaplen;
    private int network;
    private byte[] rawGlobalHeader;

    public PcapReader(String filename) throws IOException {
        this(new BufferedInputStream(new FileInputStream(filename)));
    }

    public PcapReader(InputStream inputStream) throws IOException {
        this.inputStream = inputStream;
        try {
            readGlobalHeader();
            this.open = true;
        } catch (IOException | RuntimeException exception) {
            try {
                inputStream.close();
            } catch (IOException closeException) {
                exception.addSuppressed(closeException);
            }
            throw exception;
        }
    }

    public boolean isOpen() {
        return open;
    }

    public static final class GlobalHeader {
        public int magicNumber;
        public short versionMajor;
        public short versionMinor;
        public int thisZone;
        public int sigfigs;
        public int snaplen;
        public int network;
        public boolean littleEndian;
        public byte[] rawHeader;
    }

    public static final class PacketHeader {
        public long tsSec;
        public long tsUsec;
        public long inclLen;
        public long origLen;
    }

    public static final class RawPacket {
        public PacketHeader header;
        public byte[] data;
    }

    public GlobalHeader getGlobalHeader() {
        GlobalHeader header = new GlobalHeader();
        header.magicNumber = (int) (littleEndianFile ? PCAP_MAGIC_SWAPPED : PCAP_MAGIC_NATIVE);
        header.versionMajor = (short) versionMajor;
        header.versionMinor = (short) versionMinor;
        header.thisZone = thisZone;
        header.sigfigs = sigfigs;
        header.snaplen = snaplen;
        header.network = network;
        header.littleEndian = littleEndianFile;
        header.rawHeader = rawGlobalHeader.clone();
        return header;
    }

    public boolean readNextPacket(RawPacket packet) throws IOException {
        if (!open) {
            return false;
        }

        byte[] headerBytes = new byte[16];
        int read = readFully(headerBytes);
        if (read == 0) {
            return false;
        }
        if (read < 16) {
            throw new IOException("Truncated PCAP packet header");
        }

        PacketHeader header = new PacketHeader();
        header.tsSec = readUInt32(headerBytes, 0, littleEndianFile);
        header.tsUsec = readUInt32(headerBytes, 4, littleEndianFile);
        header.inclLen = readUInt32(headerBytes, 8, littleEndianFile);
        header.origLen = readUInt32(headerBytes, 12, littleEndianFile);
        if (header.inclLen > Integer.MAX_VALUE || header.inclLen > snaplen || header.inclLen > 65535) {
            throw new IOException("Invalid packet length: " + header.inclLen);
        }

        byte[] data = new byte[(int) header.inclLen];
        int dataRead = readFully(data);
        if (dataRead < header.inclLen) {
            throw new IOException("Could not read packet data");
        }

        packet.header = header;
        packet.data = data;
        return true;
    }

    private void readGlobalHeader() throws IOException {
        byte[] buffer = new byte[24];
        int read = readFully(buffer);
        if (read < 24) {
            throw new IOException("Could not read PCAP global header");
        }
        rawGlobalHeader = buffer.clone();

        long magic = readUInt32(buffer, 0, false);
        if (magic == PCAP_MAGIC_NATIVE) {
            littleEndianFile = false;
            versionMajor = readUInt16(buffer, 4, false);
            versionMinor = readUInt16(buffer, 6, false);
            thisZone = (int) readUInt32(buffer, 8, false);
            sigfigs = (int) readUInt32(buffer, 12, false);
            snaplen = (int) readUInt32(buffer, 16, false);
            network = (int) readUInt32(buffer, 20, false);
        } else if (magic == PCAP_MAGIC_SWAPPED) {
            littleEndianFile = true;
            versionMajor = readUInt16(buffer, 4, true);
            versionMinor = readUInt16(buffer, 6, true);
            thisZone = (int) readUInt32(buffer, 8, true);
            sigfigs = (int) readUInt32(buffer, 12, true);
            snaplen = (int) readUInt32(buffer, 16, true);
            network = (int) readUInt32(buffer, 20, true);
        } else {
            throw new IOException("Invalid PCAP magic number: 0x" + Long.toHexString(magic));
        }
    }

    private int readFully(byte[] buffer) throws IOException {
        int offset = 0;
        while (offset < buffer.length) {
            int count = inputStream.read(buffer, offset, buffer.length - offset);
            if (count < 0) {
                break;
            }
            if (count == 0) {
                int value = inputStream.read();
                if (value < 0) {
                    break;
                }
                buffer[offset++] = (byte) value;
                continue;
            }
            offset += count;
        }
        return offset;
    }

    private static int readUInt16(byte[] data, int offset, boolean littleEndian) {
        ByteBuffer buffer = ByteBuffer.wrap(data, offset, 2);
        buffer.order(littleEndian ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN);
        return buffer.getShort() & 0xFFFF;
    }

    private static long readUInt32(byte[] data, int offset, boolean littleEndian) {
        ByteBuffer buffer = ByteBuffer.wrap(data, offset, 4);
        buffer.order(littleEndian ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN);
        return buffer.getInt() & 0xFFFFFFFFL;
    }

    @Override
    public void close() throws IOException {
        open = false;
        inputStream.close();
    }
}
