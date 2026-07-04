package io.quorumsentry.feature;

import io.quorumsentry.model.EventRecord;
import io.quorumsentry.model.FlowRecord;
import io.quorumsentry.model.ThreatIndicator;

public interface TelemetryFeatureExtractor {
    String name();
    FeatureVector event(EventRecord event);
    FeatureVector flow(FlowRecord flow);
    FeatureVector indicator(ThreatIndicator indicator);
}
