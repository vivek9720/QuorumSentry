package io.quorumsentry.evidence;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class EvidenceStore {
    private final Map<EvidenceKey, EvidenceScore> scores = new HashMap<>();

    public EvidenceScore score(EvidenceKey key) {
        return scores.computeIfAbsent(key, k -> new EvidenceScore());
    }

    public void observe(String kind, String value, long timestamp, int weight, int confidence) {
        EvidenceKey key = new EvidenceKey(kind, value);
        if (!key.isEmpty()) {
            score(key).observe(timestamp, weight, confidence);
        }
    }

    public List<EvidenceKey> keys() {
        List<EvidenceKey> keys = new ArrayList<>(scores.keySet());
        Collections.sort(keys);
        return keys;
    }

    public int totalScore() {
        int total = 0;
        for (EvidenceScore score : scores.values()) {
            total += score.score();
        }
        return total;
    }

    public List<EvidenceKey> actionable() {
        List<EvidenceKey> out = new ArrayList<>();
        for (Map.Entry<EvidenceKey, EvidenceScore> entry : scores.entrySet()) {
            if (entry.getValue().actionable()) {
                out.add(entry.getKey());
            }
        }
        Collections.sort(out);
        return out;
    }

    public void merge(EvidenceStore other) {
        for (EvidenceKey key : other.keys()) {
            score(key).merge(other.score(key));
        }
    }
}
