package io.quorumsentry.engine;

import io.quorumsentry.model.EventRecord;
import io.quorumsentry.model.FlowRecord;
import io.quorumsentry.model.ThreatIndicator;
import java.util.ArrayList;
import java.util.List;

public final class TelemetryBatch {
    private final List<EventRecord> events = new ArrayList<>();
    private final List<FlowRecord> flows = new ArrayList<>();
    private final List<ThreatIndicator> indicators = new ArrayList<>();

    public List<EventRecord> events() { return events; }
    public List<FlowRecord> flows() { return flows; }
    public List<ThreatIndicator> indicators() { return indicators; }

    public boolean isEmpty() {
        return events.isEmpty() && flows.isEmpty() && indicators.isEmpty();
    }

    public int size() {
        return events.size() + flows.size() + indicators.size();
    }
}
