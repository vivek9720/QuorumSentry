package io.quorumsentry.detect;

import io.quorumsentry.evidence.EvidenceStore;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public final class DetectionContext {
    private final EvidenceStore evidence = new EvidenceStore();
    private final List<Finding> findings = new ArrayList<>();

    public EvidenceStore evidence() {
        return evidence;
    }

    public void add(Finding finding) {
        findings.add(finding);
    }

    public List<Finding> findings() {
        findings.sort((a, b) -> Integer.compare(b.priority(), a.priority()));
        return Collections.unmodifiableList(findings);
    }

    public boolean hasFindings() {
        return !findings.isEmpty();
    }
}
