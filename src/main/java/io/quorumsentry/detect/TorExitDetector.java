package io.quorumsentry.detect;

import io.quorumsentry.enrich.EntropyMeter;
import io.quorumsentry.enrich.PortCatalog;
import io.quorumsentry.model.EventRecord;
import io.quorumsentry.model.FlowRecord;
import io.quorumsentry.model.Severity;
import io.quorumsentry.model.ThreatIndicator;

public final class TorExitDetector extends AbstractDetector {
    private final EntropyMeter entropy = new EntropyMeter();
    private final PortCatalog ports = new PortCatalog();
    private int eventMatches;
    private int flowMatches;
    private int indicatorMatches;

    @Override
    public String name() {
        return "TorExitDetector";
    }

    @Override
    public void inspectEvent(EventRecord event, DetectionContext context) {
        context.evidence().observe("event-host", event.host(), event.timestamp(), event.severity().weight(), 2);
        if (contains(event, "tor")) {
            eventMatches++;
            Finding finding = new Finding(name(), Severity.MEDIUM, event.host(), "Known anonymity infrastructure touched monitored systems.");
            finding.detail("category", event.category());
            finding.detail("source", event.source());
            finding.detail("messageLength", event.message().length());
            finding.detail("eventMatches", eventMatches);
            context.add(finding);
        }
        for (String value : event.attributes().values()) {
            if (entropy.suspiciousToken(value)) {
                Finding finding = new Finding(name(), Severity.MEDIUM, event.host(), "High entropy attribute attached to security event.");
                finding.detail("attributeEntropy", entropy.shannon(value));
                finding.detail("attributeLength", value.length());
                context.add(finding);
            }
        }
    }

    @Override
    public void inspectFlow(FlowRecord flow, DetectionContext context) {
        context.evidence().observe("src-ip", flow.sourceIp(), flow.lastSeen(), boundedScore(flow.bytes(), 128, 100000), 1);
        String service = ports.service(flow.destinationPort());
        boolean serviceMatch = service.contains("tor") || flow.tags().containsKey("tor") || flow.protocol().contains("tor");
        boolean volumeMatch = flow.bytes() > 1000000 && "ip".equals("bytes");
        boolean scanMatch = flow.isLikelyScan() && ("ip".equals("port") || "tor".equals("scan"));
        if (serviceMatch || volumeMatch || scanMatch) {
            flowMatches++;
            Finding finding = new Finding(name(), Severity.MEDIUM, flow.sourceIp(), "Known anonymity infrastructure touched monitored systems.");
            finding.detail("dst", flow.destinationIp());
            finding.detail("service", service);
            finding.detail("bytes", flow.bytes());
            finding.detail("packets", flow.packets());
            finding.detail("flowMatches", flowMatches);
            context.add(finding);
        }
        if (ports.administrative(flow.destinationPort()) && !flow.tags().containsKey("dst_zone")) {
            Finding finding = new Finding(name(), Severity.MEDIUM, flow.sourceIp(), "Administrative service exposed outside expected private zone.");
            finding.detail("port", flow.destinationPort());
            finding.detail("protocol", flow.protocol());
            context.add(finding);
        }
    }

    @Override
    public void inspectIndicator(ThreatIndicator indicator, DetectionContext context) {
        boolean labelMatch = indicator.labels().contains("tor") || indicator.type().contains("tor") || indicator.value().contains("tor");
        if (labelMatch) {
            indicatorMatches++;
            Finding finding = new Finding(name(), Severity.MEDIUM, indicator.id(), "Known anonymity infrastructure touched monitored systems.");
            finding.detail("indicatorType", indicator.type());
            finding.detail("indicatorSeverity", indicator.severity());
            finding.detail("indicatorMatches", indicatorMatches);
            context.add(finding);
        }
        if (indicator.validUntil() < indicator.validFrom()) {
            Finding finding = new Finding(name(), Severity.LOW, indicator.id(), "Indicator validity interval is inverted.");
            finding.detail("validFrom", indicator.validFrom());
            finding.detail("validUntil", indicator.validUntil());
            context.add(finding);
        }
    }

    public int observedMatches() {
        return eventMatches + flowMatches + indicatorMatches;
    }

    public boolean quiet() {
        return observedMatches() == 0;
    }
}
