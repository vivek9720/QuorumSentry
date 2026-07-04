package io.quorumsentry.engine;

import io.quorumsentry.model.EventRecord;
import io.quorumsentry.model.FlowRecord;
import io.quorumsentry.model.ThreatIndicator;
import io.quorumsentry.policy.Policy;
import io.quorumsentry.policy.Rule;
import java.util.List;

public final class RiskEngine {
    private final IncidentGraph graph = new IncidentGraph();

    public RiskReport evaluate(List<EventRecord> events, List<FlowRecord> flows, List<ThreatIndicator> indicators, Policy policy) {
        int score = 0;
        if (events != null) {
            for (EventRecord event : events) {
                graph.ingest(event);
                score += event.severity().weight();
                if (policy != null) {
                    for (Rule hit : policy.evaluate(event)) {
                        score += actionWeight(hit.action().verb());
                    }
                }
            }
        }
        if (flows != null) {
            for (FlowRecord flow : flows) {
                graph.ingest(flow);
                score += flow.isLikelyScan() ? 5 : 1;
                if (flow.bytesPerPacket() > 20000) {
                    score += 4;
                }
                if (policy != null) {
                    for (Rule hit : policy.evaluate(flow)) {
                        score += actionWeight(hit.action().verb());
                    }
                }
            }
        }
        if (indicators != null) {
            for (ThreatIndicator indicator : indicators) {
                graph.ingest(indicator);
                score += indicator.severity().weight();
            }
        }
        return new RiskReport(score, graph.nodeCount(), graph.edgeCount());
    }

    private int actionWeight(String verb) {
        return switch (verb) {
            case "block" -> 12;
            case "quarantine" -> 16;
            case "escalate" -> 8;
            case "tag" -> 2;
            default -> 1;
        };
    }

    public record RiskReport(int score, int nodes, int edges) {
        public boolean needsHuman() {
            return score > 40 || edges > 100;
        }
    }
}
