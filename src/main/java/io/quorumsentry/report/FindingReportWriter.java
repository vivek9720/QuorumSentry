package io.quorumsentry.report;

import io.quorumsentry.detect.Finding;
import java.util.List;
import java.util.Map;

public final class FindingReportWriter {
    public String markdown(List<Finding> findings) {
        StringBuilder out = new StringBuilder();
        out.append("# Findings\n\n");
        for (Finding finding : findings) {
            out.append("## ").append(finding.detector()).append("\n\n");
            out.append("- Severity: ").append(finding.severity()).append('\n');
            out.append("- Subject: ").append(finding.subject()).append('\n');
            out.append("- Summary: ").append(finding.summary()).append('\n');
            for (Map.Entry<String, String> detail : finding.details().entrySet()) {
                out.append("- ").append(detail.getKey()).append(": ").append(detail.getValue()).append('\n');
            }
            out.append('\n');
        }
        return out.toString();
    }
}
