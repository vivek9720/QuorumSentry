package io.quorumsentry.report;

import io.quorumsentry.engine.RiskEngine;
import io.quorumsentry.engine.QuarantinePlanner;

public final class JsonReportWriter {
    public String write(RiskEngine.RiskReport report, QuarantinePlanner.Plan plan) {
        StringBuilder out = new StringBuilder();
        out.append("{");
        out.append("\"score\":").append(report.score()).append(',');
        out.append("\"nodes\":").append(report.nodes()).append(',');
        out.append("\"edges\":").append(report.edges()).append(',');
        out.append("\"needsHuman\":").append(report.needsHuman()).append(',');
        out.append("\"isolate\":[");
        for (int i = 0; i < plan.isolate().size(); i++) {
            if (i > 0) out.append(',');
            out.append('"').append(escape(plan.isolate().get(i))).append('"');
        }
        out.append("],\"watch\":[");
        for (int i = 0; i < plan.watch().size(); i++) {
            if (i > 0) out.append(',');
            out.append('"').append(escape(plan.watch().get(i))).append('"');
        }
        out.append("]}");
        return out.toString();
    }

    private String escape(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
