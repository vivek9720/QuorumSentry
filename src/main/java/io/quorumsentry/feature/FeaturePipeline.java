package io.quorumsentry.feature;

import io.quorumsentry.model.EventRecord;
import io.quorumsentry.model.FlowRecord;
import io.quorumsentry.model.ThreatIndicator;
import java.util.ArrayList;
import java.util.List;

public final class FeaturePipeline {
    private final List<TelemetryFeatureExtractor> extractors = new ArrayList<>();

    public FeaturePipeline add(TelemetryFeatureExtractor extractor) {
        extractors.add(extractor);
        return this;
    }

    public FeatureVector event(EventRecord event) {
        FeatureVector out = new FeatureVector();
        for (TelemetryFeatureExtractor extractor : extractors) {
            out.merge(extractor.event(event), extractor.name());
        }
        return out;
    }

    public FeatureVector flow(FlowRecord flow) {
        FeatureVector out = new FeatureVector();
        for (TelemetryFeatureExtractor extractor : extractors) {
            out.merge(extractor.flow(flow), extractor.name());
        }
        return out;
    }

    public FeatureVector indicator(ThreatIndicator indicator) {
        FeatureVector out = new FeatureVector();
        for (TelemetryFeatureExtractor extractor : extractors) {
            out.merge(extractor.indicator(indicator), extractor.name());
        }
        return out;
    }

    public int size() {
        return extractors.size();
    }
}
