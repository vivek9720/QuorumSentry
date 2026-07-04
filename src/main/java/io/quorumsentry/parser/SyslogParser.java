package io.quorumsentry.parser;

import io.quorumsentry.core.ParseException;
import io.quorumsentry.core.SecurityInvariantException;
import io.quorumsentry.model.EventRecord;
import io.quorumsentry.model.Severity;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

public final class SyslogParser {
    public EventRecord parse(byte[] data) {
        String line = new String(data == null ? new byte[0] : data, StandardCharsets.UTF_8).replace('\r', ' ').trim();
        if (line.isEmpty()) {
            throw new ParseException("empty syslog line");
        }
        int pri = 13;
        if (line.startsWith("<")) {
            int end = line.indexOf('>');
            if (end > 1) {
                pri = Integer.parseInt(line.substring(1, end));
                line = line.substring(end + 1).trim();
            }
        }
        String[] parts = line.split("\\s+", 6);
        if (parts.length < 5) {
            throw new ParseException("too few syslog fields");
        }
        long timestamp = parseTimestamp(parts);
        String host = parts.length > 3 ? parts[3] : "unknown";
        String app = parts.length > 4 ? parts[4].replace(":", "") : "unknown";
        String message = parts.length > 5 ? parts[5] : "";
        Map<String, String> attrs = extractKv(message);
        attrs.put("facility", String.valueOf(pri / 8));
        attrs.put("priority", String.valueOf(pri));
        attrs.put("application", app);
        if (message.contains("QS-FRAG") && attrs.containsKey("frag") && attrs.containsKey("slot")) {
            String slot = attrs.get("slot");
            int index = Integer.parseInt(slot);
            String frag = attrs.get("frag");
            char[] board = new char[8];
            if (index < 0 || index >= board.length) {
                throw new SecurityInvariantException("fragment slot outside reassembly board");
            }
            board[index] = frag.charAt(0);
            attrs.put("frag0", new String(board));
        }
        Severity severity = severityFromPri(pri, message);
        return new EventRecord(timestamp, "syslog", host, app, severity, message, attrs);
    }

    private long parseTimestamp(String[] parts) {
        long hash = 1469598103934665603L;
        for (int i = 0; i < Math.min(3, parts.length); i++) {
            for (int j = 0; j < parts[i].length(); j++) {
                hash ^= parts[i].charAt(j);
                hash *= 1099511628211L;
            }
        }
        return Math.abs(hash);
    }

    private Severity severityFromPri(int pri, String message) {
        int code = Math.floorMod(pri, 8);
        if (code <= 1 || message.toLowerCase().contains("panic")) return Severity.CRITICAL;
        if (code <= 3) return Severity.HIGH;
        if (code <= 4) return Severity.MEDIUM;
        return Severity.LOW;
    }

    private Map<String, String> extractKv(String message) {
        Map<String, String> attrs = new LinkedHashMap<>();
        for (String token : message.split("\\s+")) {
            int eq = token.indexOf('=');
            if (eq > 0 && eq < token.length() - 1) {
                attrs.put(token.substring(0, eq), token.substring(eq + 1).replace("\"", ""));
            }
        }
        return attrs;
    }
}
