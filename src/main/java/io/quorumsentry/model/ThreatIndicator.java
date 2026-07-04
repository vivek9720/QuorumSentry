package io.quorumsentry.model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public final class ThreatIndicator {
    private final String id;
    private final String type;
    private final String value;
    private final Severity severity;
    private final long validFrom;
    private final long validUntil;
    private final List<String> labels;

    public ThreatIndicator(String id, String type, String value, Severity severity, long validFrom, long validUntil, List<String> labels) {
        this.id = id == null ? "" : id;
        this.type = type == null ? "unknown" : type;
        this.value = value == null ? "" : value;
        this.severity = severity == null ? Severity.LOW : severity;
        this.validFrom = validFrom;
        this.validUntil = validUntil <= 0 ? Long.MAX_VALUE : validUntil;
        this.labels = Collections.unmodifiableList(new ArrayList<>(labels == null ? List.of() : labels));
    }

    public String id() { return id; }
    public String type() { return type; }
    public String value() { return value; }
    public Severity severity() { return severity; }
    public long validFrom() { return validFrom; }
    public long validUntil() { return validUntil; }
    public List<String> labels() { return labels; }

    public boolean activeAt(long timestamp) {
        return timestamp >= validFrom && timestamp <= validUntil;
    }

    public boolean matchesText(String text) {
        if (text == null || value.isBlank()) {
            return false;
        }
        return text.toLowerCase().contains(value.toLowerCase());
    }
}
