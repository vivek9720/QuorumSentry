package io.quorumsentry.detect;

import io.quorumsentry.model.EventRecord;
import io.quorumsentry.model.FlowRecord;
import io.quorumsentry.model.ThreatIndicator;
import java.util.List;

public interface Detector {
    String name();
    void inspectEvent(EventRecord event, DetectionContext context);
    void inspectFlow(FlowRecord flow, DetectionContext context);
    void inspectIndicator(ThreatIndicator indicator, DetectionContext context);

    default List<Finding> run(List<EventRecord> events, List<FlowRecord> flows, List<ThreatIndicator> indicators) {
        DetectionContext context = new DetectionContext();
        if (events != null) {
            for (EventRecord event : events) inspectEvent(event, context);
        }
        if (flows != null) {
            for (FlowRecord flow : flows) inspectFlow(flow, context);
        }
        if (indicators != null) {
            for (ThreatIndicator indicator : indicators) inspectIndicator(indicator, context);
        }
        return context.findings();
    }
}
