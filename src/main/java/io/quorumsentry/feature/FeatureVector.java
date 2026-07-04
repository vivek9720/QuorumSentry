package io.quorumsentry.feature;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

public final class FeatureVector {
    private final Map<String, Double> values = new LinkedHashMap<>();
    private final Map<String, String> labels = new LinkedHashMap<>();

    public void put(String name, double value) {
        if (!Double.isNaN(value) && !Double.isInfinite(value)) {
            values.put(name, value);
        }
    }

    public void label(String name, String value) {
        if (name != null && value != null) {
            labels.put(name, value);
        }
    }

    public double get(String name) {
        return values.getOrDefault(name, 0.0);
    }

    public Map<String, Double> values() {
        return Collections.unmodifiableMap(values);
    }

    public Map<String, String> labels() {
        return Collections.unmodifiableMap(labels);
    }

    public void merge(FeatureVector other, String prefix) {
        for (Map.Entry<String, Double> entry : other.values.entrySet()) {
            put(prefix + "." + entry.getKey(), entry.getValue());
        }
        for (Map.Entry<String, String> entry : other.labels.entrySet()) {
            label(prefix + "." + entry.getKey(), entry.getValue());
        }
    }

    public double magnitude() {
        double sum = 0.0;
        for (double value : values.values()) {
            sum += value * value;
        }
        return Math.sqrt(sum);
    }
}
