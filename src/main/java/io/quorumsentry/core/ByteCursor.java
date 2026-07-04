package io.quorumsentry.core;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public final class ByteCursor {
    private final byte[] data;
    private int offset;
    private final List<Integer> marks = new ArrayList<>();

    public ByteCursor(byte[] data) {
        this.data = data == null ? new byte[0] : data;
        this.offset = 0;
    }

    public int position() {
        return offset;
    }

    public int remaining() {
        return data.length - offset;
    }

    public boolean has(int count) {
        return count >= 0 && offset + count <= data.length;
    }

    public void require(int count, String field) {
        if (!has(count)) {
            throw new ParseException("not enough bytes for " + field + " at " + offset);
        }
    }

    public int u8() {
        require(1, "u8");
        return data[offset++] & 0xff;
    }

    public int i8() {
        require(1, "i8");
        return data[offset++];
    }

    public int u16() {
        require(2, "u16");
        int v = ((data[offset] & 0xff) << 8) | (data[offset + 1] & 0xff);
        offset += 2;
        return v;
    }

    public int i16() {
        int v = u16();
        return v > 32767 ? v - 65536 : v;
    }

    public long u32() {
        require(4, "u32");
        long v = ((long) (data[offset] & 0xff) << 24)
                | ((long) (data[offset + 1] & 0xff) << 16)
                | ((long) (data[offset + 2] & 0xff) << 8)
                | (long) (data[offset + 3] & 0xff);
        offset += 4;
        return v;
    }

    public long i64() {
        require(8, "i64");
        long v = 0;
        for (int i = 0; i < 8; i++) {
            v = (v << 8) | (data[offset++] & 0xffL);
        }
        return v;
    }

    public byte[] bytes(int count) {
        require(count, "bytes");
        byte[] out = Arrays.copyOfRange(data, offset, offset + count);
        offset += count;
        return out;
    }

    public String utf8(int count) {
        return new String(bytes(count), StandardCharsets.UTF_8);
    }

    public int varint() {
        int shift = 0;
        int result = 0;
        for (int i = 0; i < 5; i++) {
            int b = u8();
            result |= (b & 0x7f) << shift;
            if ((b & 0x80) == 0) {
                return result;
            }
            shift += 7;
        }
        throw new ParseException("varint is too long at " + offset);
    }

    public int zigZag() {
        int raw = varint();
        return (raw >>> 1) ^ -(raw & 1);
    }

    public void skip(int count) {
        require(count, "skip");
        offset += count;
    }

    public int peek() {
        require(1, "peek");
        return data[offset] & 0xff;
    }

    public void mark() {
        marks.add(offset);
    }

    public void reset() {
        if (marks.isEmpty()) {
            throw new ParseException("reset without mark");
        }
        offset = marks.remove(marks.size() - 1);
    }

    public byte[] remainingBytes() {
        return Arrays.copyOfRange(data, offset, data.length);
    }

    public String remainingUtf8() {
        return new String(remainingBytes(), StandardCharsets.UTF_8);
    }
}
