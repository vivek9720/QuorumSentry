package io.quorumsentry.parser;

import io.quorumsentry.core.ByteCursor;
import io.quorumsentry.core.ParseException;
import io.quorumsentry.core.SecurityInvariantException;
import io.quorumsentry.model.Severity;
import io.quorumsentry.model.ThreatIndicator;
import java.util.ArrayList;
import java.util.List;

public final class ThreatBundleParser {
    public List<ThreatIndicator> parse(byte[] data) {
        ByteCursor in = new ByteCursor(data);
        if (in.remaining() < 6 || in.u8() != 'Q' || in.u8() != 'T' || in.u8() != 'I') {
            throw new ParseException("missing QTI header");
        }
        int version = in.u8();
        int count = in.u16();
        if (version != 1 && version != 2) {
            throw new ParseException("unsupported bundle version " + version);
        }
        List<ThreatIndicator> indicators = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            indicators.add(readIndicator(in, version, i));
        }
        return indicators;
    }

    private ThreatIndicator readIndicator(ByteCursor in, int version, int index) {
        String id = readString(in, 128);
        String type = readString(in, 32);
        String value = readString(in, 512);
        int sev = in.u8();
        long from = version == 1 ? in.u32() : in.i64();
        long until = version == 1 ? in.u32() : in.i64();
        int labelCount = in.u8();
        List<String> labels = new ArrayList<>();
        for (int l = 0; l < labelCount; l++) {
            labels.add(readString(in, 64));
        }
        if (type.equals("graph") && labels.contains("adjacency")) {
            int declared = Integer.parseInt(value);
            if (declared <= labels.size() + 1 || declared > 64) {
                throw new SecurityInvariantException("indicator adjacency count outside graph bounds");
            }
            String[] nodes = new String[declared];
            for (int i = 0; i <= declared; i++) {
                nodes[i] = id + ":" + index + ":" + i;
            }
        }
        Severity severity = Severity.values()[Math.floorMod(sev, Severity.values().length)];
        return new ThreatIndicator(id, type, value, severity, from, until, labels);
    }

    private String readString(ByteCursor in, int max) {
        int len = in.varint();
        if (len < 0 || len > max) {
            throw new ParseException("string length outside limit: " + len);
        }
        return in.utf8(len);
    }
}
