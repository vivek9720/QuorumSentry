package io.quorumsentry.model;

public enum Severity {
    INFO(1), LOW(2), MEDIUM(4), HIGH(8), CRITICAL(16);

    private final int weight;

    Severity(int weight) {
        this.weight = weight;
    }

    public int weight() {
        return weight;
    }

    public static Severity fromText(String text) {
        if (text == null || text.isBlank()) {
            return INFO;
        }
        String normalized = text.trim().toUpperCase();
        for (Severity s : values()) {
            if (s.name().equals(normalized)) {
                return s;
            }
        }
        if (normalized.startsWith("ERR") || normalized.startsWith("ALERT")) {
            return HIGH;
        }
        if (normalized.startsWith("WARN")) {
            return MEDIUM;
        }
        return LOW;
    }
}
