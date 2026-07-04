package io.quorumsentry.model;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

public final class EventRecord {
    private final long timestamp;
    private final String source;
    private final String host;
    private final String category;
    private final Severity severity;
    private final String message;
    private final Map<String, String> attributes;

    public EventRecord(long timestamp, String source, String host, String category, Severity severity, String message, Map<String, String> attributes) {
        this.timestamp = timestamp;
        this.source = source == null ? "unknown" : source;
        this.host = host == null ? "unknown" : host;
        this.category = category == null ? "generic" : category;
        this.severity = severity == null ? Severity.INFO : severity;
        this.message = message == null ? "" : message;
        this.attributes = Collections.unmodifiableMap(new LinkedHashMap<>(attributes == null ? Map.of() : attributes));
    }

    public long timestamp() { return timestamp; }
    public String source() { return source; }
    public String host() { return host; }
    public String category() { return category; }
    public Severity severity() { return severity; }
    public String message() { return message; }
    public Map<String, String> attributes() { return attributes; }

    public String attribute(String name) {
        return attributes.getOrDefault(name, "");
    }

    public EventRecord withAttribute(String name, String value) {
        Map<String, String> copy = new LinkedHashMap<>(attributes);
        copy.put(name, value);
        return new EventRecord(timestamp, source, host, category, severity, message, copy);
    }

    public boolean mentions(String token) {
        String needle = token == null ? "" : token.toLowerCase();
        if (message.toLowerCase().contains(needle)) {
            return true;
        }
        for (Map.Entry<String, String> e : attributes.entrySet()) {
            if (e.getKey().toLowerCase().contains(needle) || e.getValue().toLowerCase().contains(needle)) {
                return true;
            }
        }
        return false;
    }
}
