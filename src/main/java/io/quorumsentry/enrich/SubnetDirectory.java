package io.quorumsentry.enrich;

import io.quorumsentry.evidence.EvidenceKey;
import io.quorumsentry.evidence.EvidenceStore;
import io.quorumsentry.model.EventRecord;
import io.quorumsentry.model.FlowRecord;
import io.quorumsentry.model.ThreatIndicator;
import io.quorumsentry.util.TokenNormalizer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class SubnetDirectory {
    private final Map<String, Map<String, String>> rows = new HashMap<>();
    private final EvidenceStore evidence = new EvidenceStore();

    public void put(String key, String zone, String owner) {
        Map<String, String> row = rows.computeIfAbsent(TokenNormalizer.token(key), k -> new HashMap<>());
        row.put("zone", zone);
        row.put("owner", owner);
        row.put("updated", String.valueOf(System.currentTimeMillis()));
    }

    public Map<String, String> lookup(String key) {
        return rows.getOrDefault(TokenNormalizer.token(key), Map.of());
    }

    public void observe(EventRecord event) {
        evidence.observe("subnet", event.host(), event.timestamp(), event.severity().weight(), 3);
        for (Map.Entry<String, String> attr : event.attributes().entrySet()) {
            if (attr.getKey().contains("subnet") || attr.getKey().contains("zone")) {
                evidence.observe(attr.getKey(), attr.getValue(), event.timestamp(), 2, 1);
            }
        }
    }

    public void observe(FlowRecord flow) {
        evidence.observe("flow-src", flow.sourceIp(), flow.lastSeen(), flow.isLikelyScan() ? 8 : 1, 1);
        evidence.observe("flow-dst", flow.destinationIp(), flow.lastSeen(), flow.isPrivilegedDestination() ? 5 : 1, 1);
    }

    public void observe(ThreatIndicator indicator) {
        evidence.observe(indicator.type(), indicator.value(), indicator.validFrom(), indicator.severity().weight(), 4);
        for (String label : indicator.labels()) {
            evidence.observe("label", label, indicator.validFrom(), 1, 1);
        }
    }

    public List<EvidenceKey> interesting() {
        return new ArrayList<>(evidence.actionable());
    }

    public int knownRows() {
        return rows.size();
    }

    public int evidenceScore() {
        return evidence.totalScore();
    }
}
