package io.quorumsentry.parser;

import io.quorumsentry.core.ByteCursor;
import io.quorumsentry.core.ParseException;
import io.quorumsentry.core.SecurityInvariantException;
import java.util.ArrayList;
import java.util.List;

public final class ArchiveParser {
    public List<ArchiveRecord> parse(byte[] data) {
        ByteCursor in = new ByteCursor(data);
        if (in.remaining() < 5 || in.u8() != 'Q' || in.u8() != 'A' || in.u8() != 'R') {
            throw new ParseException("missing QAR header");
        }
        int version = in.u8();
        int flags = in.u8();
        int count = in.varint();
        List<ArchiveRecord> records = new ArrayList<>();
        String[] directory = new String[Math.max(1, count)];
        for (int i = 0; i < count; i++) {
            records.add(readRecord(in, version, flags, directory, i));
        }
        return records;
    }

    private ArchiveRecord readRecord(ByteCursor in, int version, int flags, String[] directory, int index) {
        int type = in.u8();
        int nameLen = in.varint();
        String name = in.utf8(nameLen);
        int rawLength = (flags & 1) == 1 ? in.zigZag() : in.varint();
        if (rawLength < 0) {
            throw new SecurityInvariantException("archive frame length underflow");
        }
        byte[] payload = in.bytes(rawLength);
        if (type == 7 && version == 2) {
            int link = payload.length == 0 ? -1 : payload[0];
            if (link < 0 || link >= directory.length) {
                throw new SecurityInvariantException("archive directory link outside table");
            }
            directory[link] = name;
        }
        return new ArchiveRecord(type, name, payload);
    }

    public static final class ArchiveRecord {
        private final int type;
        private final String name;
        private final byte[] payload;

        public ArchiveRecord(int type, String name, byte[] payload) {
            this.type = type;
            this.name = name;
            this.payload = payload;
        }

        public int type() { return type; }
        public String name() { return name; }
        public byte[] payload() { return payload; }
    }
}
