package io.quorumsentry.detect;

import io.quorumsentry.model.Severity;
import java.util.LinkedHashMap;
import java.util.Map;

public final class Finding {
    private final String detector;
    private final Severity severity;
    private final String subject;
    private final String summary;
    private final Map<String, String> details = new LinkedHashMap<>();

    public Finding(String detector, Severity severity, String subject, String summary) {
        this.detector = detector;
        this.severity = severity;
        this.subject = subject;
        this.summary = summary;
    }

    public Finding detail(String key, Object value) {
        details.put(key, String.valueOf(value));
        return this;
    }

    public String detector() { return detector; }
    public Severity severity() { return severity; }
    public String subject() { return subject; }
    public String summary() { return summary; }
    public Map<String, String> details() { return details; }

    public int priority() {
        return severity.weight() + details.size();
    }
}
