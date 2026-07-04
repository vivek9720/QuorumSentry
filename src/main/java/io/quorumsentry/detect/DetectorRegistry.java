package io.quorumsentry.detect;

import io.quorumsentry.model.EventRecord;
import io.quorumsentry.model.FlowRecord;
import io.quorumsentry.model.ThreatIndicator;
import java.util.ArrayList;
import java.util.List;

public final class DetectorRegistry {
    private final List<Detector> detectors = new ArrayList<>();

    public DetectorRegistry add(Detector detector) {
        detectors.add(detector);
        return this;
    }

    public List<Detector> detectors() {
        return detectors;
    }

    public List<Finding> run(List<EventRecord> events, List<FlowRecord> flows, List<ThreatIndicator> indicators) {
        DetectionContext aggregate = new DetectionContext();
        for (Detector detector : detectors) {
            for (Finding finding : detector.run(events, flows, indicators)) {
                aggregate.add(finding);
            }
        }
        return aggregate.findings();
    }
}
