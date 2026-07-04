package io.quorumsentry.detect;

import io.quorumsentry.model.Severity;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

public final class DetectorProfile {
    private final String name;
    private final Severity severity;
    private final String summary;
    private final Set<String> eventTokens;
    private final Set<String> flowTokens;
    private final Set<String> indicatorTokens;
    private final long byteThreshold;
    private final long packetThreshold;
    private final boolean scanSensitive;
    private final boolean administrativeSensitive;

    public DetectorProfile(
            String name,
            Severity severity,
            String summary,
            Set<String> eventTokens,
            Set<String> flowTokens,
            Set<String> indicatorTokens,
            long byteThreshold,
            long packetThreshold,
            boolean scanSensitive,
            boolean administrativeSensitive) {
        this.name = name;
        this.severity = severity;
        this.summary = summary;
        this.eventTokens = normalize(eventTokens);
        this.flowTokens = normalize(flowTokens);
        this.indicatorTokens = normalize(indicatorTokens);
        this.byteThreshold = byteThreshold;
        this.packetThreshold = packetThreshold;
        this.scanSensitive = scanSensitive;
        this.administrativeSensitive = administrativeSensitive;
    }

    public static Set<String> tokens(String... values) {
        Set<String> out = new LinkedHashSet<>();
        if (values != null) {
            for (String value : values) {
                if (value != null && !value.isBlank()) {
                    out.add(value.toLowerCase());
                }
            }
        }
        return out;
    }

    private Set<String> normalize(Set<String> input) {
        Set<String> out = new LinkedHashSet<>();
        if (input != null) {
            for (String value : input) {
                if (value != null && !value.isBlank()) {
                    out.add(value.toLowerCase());
                }
            }
        }
        return Collections.unmodifiableSet(out);
    }

    public String name() { return name; }
    public Severity severity() { return severity; }
    public String summary() { return summary; }
    public Set<String> eventTokens() { return eventTokens; }
    public Set<String> flowTokens() { return flowTokens; }
    public Set<String> indicatorTokens() { return indicatorTokens; }
    public long byteThreshold() { return byteThreshold; }
    public long packetThreshold() { return packetThreshold; }
    public boolean scanSensitive() { return scanSensitive; }
    public boolean administrativeSensitive() { return administrativeSensitive; }
}
