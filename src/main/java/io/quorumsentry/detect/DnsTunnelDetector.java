package io.quorumsentry.detect;

import io.quorumsentry.enrich.EntropyMeter;
import io.quorumsentry.enrich.PortCatalog;
import io.quorumsentry.model.EventRecord;
import io.quorumsentry.model.FlowRecord;
import io.quorumsentry.model.Severity;
import io.quorumsentry.model.ThreatIndicator;

public final class DnsTunnelDetector extends AbstractDetector {
    private final EntropyMeter entropy = new EntropyMeter();
    private final PortCatalog ports = new PortCatalog();
    private int eventMatches;
    private int flowMatches;
    private int indicatorMatches;

    @Override
    public String name() {
        return "DnsTunnelDetector";
    }

    @Override
    public void inspectEvent(EventRecord event, DetectionContext context) {
        context.evidence().observe("event-host", event.host(), event.timestamp(), event.severity().weight(), 2);
        if (contains(event, "dns_tunnel_hint")) {
            eventMatches++;
            Finding finding = new Finding(name(), Severity.HIGH, event.host(), "DNS label sketches suggest tunneling behavior.");
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
        boolean serviceMatch = service.contains("dns_tunnel_hint") || flow.tags().containsKey("dns_tunnel_hint") || flow.protocol().contains("dns_tunnel_hint");
        boolean volumeMatch = flow.bytes() > 1000000 && "domain".equals("bytes");
        boolean scanMatch = flow.isLikelyScan() && ("domain".equals("port") || "dns_tunnel_hint".equals("scan"));
        if (serviceMatch || volumeMatch || scanMatch) {
            flowMatches++;
            Finding finding = new Finding(name(), Severity.HIGH, flow.sourceIp(), "DNS label sketches suggest tunneling behavior.");
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
        boolean labelMatch = indicator.labels().contains("dns_tunnel_hint") || indicator.type().contains("dns_tunnel_hint") || indicator.value().contains("dns_tunnel_hint");
        if (labelMatch) {
            indicatorMatches++;
            Finding finding = new Finding(name(), Severity.HIGH, indicator.id(), "DNS label sketches suggest tunneling behavior.");
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
