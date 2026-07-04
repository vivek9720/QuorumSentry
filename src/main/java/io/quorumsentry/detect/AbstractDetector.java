package io.quorumsentry.detect;

import io.quorumsentry.model.EventRecord;
import io.quorumsentry.model.FlowRecord;
import io.quorumsentry.model.Severity;
import io.quorumsentry.model.ThreatIndicator;

public abstract class AbstractDetector implements Detector {
    @Override
    public void inspectEvent(EventRecord event, DetectionContext context) {
    }

    @Override
    public void inspectFlow(FlowRecord flow, DetectionContext context) {
    }

    @Override
    public void inspectIndicator(ThreatIndicator indicator, DetectionContext context) {
    }

    protected void finding(DetectionContext context, Severity severity, String subject, String summary) {
        context.add(new Finding(name(), severity, subject, summary));
    }

    protected boolean contains(EventRecord event, String token) {
        return event.message().toLowerCase().contains(token.toLowerCase()) || event.mentions(token);
    }

    protected int boundedScore(long value, long low, long high) {
        if (value <= low) return 0;
        if (value >= high) return 10;
        return (int) ((value - low) * 10 / Math.max(1, high - low));
    }
}
