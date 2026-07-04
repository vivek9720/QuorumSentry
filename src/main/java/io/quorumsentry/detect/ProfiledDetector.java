package io.quorumsentry.detect;

import io.quorumsentry.enrich.EntropyMeter;
import io.quorumsentry.enrich.PortCatalog;
import io.quorumsentry.model.EventRecord;
import io.quorumsentry.model.FlowRecord;
import io.quorumsentry.model.Severity;
import io.quorumsentry.model.ThreatIndicator;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public abstract class ProfiledDetector extends AbstractDetector {
    private final DetectorProfile profile;
    private final EntropyMeter entropy = new EntropyMeter();
    private final PortCatalog ports = new PortCatalog();
    private int eventMatches;
    private int flowMatches;
    private int indicatorMatches;

    protected ProfiledDetector(DetectorProfile profile) {
        this.profile = profile;
    }

    @Override
    public String name() {
        return profile.name();
    }

    @Override
    public void inspectEvent(EventRecord event, DetectionContext context) {
        context.evidence().observe("event-host", event.host(), event.timestamp(), event.severity().weight(), 2);
        int tokenHits = tokenHits(profile.eventTokens(), event.message(), event.attributes());
        if (tokenHits > 0 || event.severity().weight() >= profile.severity().weight() && event.mentions("denied")) {
            eventMatches++;
            Finding finding = new Finding(name(), profile.severity(), event.host(), profile.summary());
            finding.detail("category", event.category());
            finding.detail("source", event.source());
            finding.detail("tokenHits", tokenHits);
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
        int flowTokenHits = tokenHits(profile.flowTokens(), service, flow.protocol(), flow.tags());
        boolean volumeMatch = profile.byteThreshold() > 0 && flow.bytes() >= profile.byteThreshold();
        boolean packetMatch = profile.packetThreshold() > 0 && flow.packets() >= profile.packetThreshold();
        boolean scanMatch = profile.scanSensitive() && flow.isLikelyScan();
        boolean adminMatch = profile.administrativeSensitive() && ports.administrative(flow.destinationPort());
        if (flowTokenHits > 0 || volumeMatch || packetMatch || scanMatch || adminMatch) {
            flowMatches++;
            Finding finding = new Finding(name(), profile.severity(), flow.sourceIp(), profile.summary());
            finding.detail("dst", flow.destinationIp());
            finding.detail("service", service);
            finding.detail("bytes", flow.bytes());
            finding.detail("packets", flow.packets());
            finding.detail("tokenHits", flowTokenHits);
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
        int tokenHits = tokenHits(profile.indicatorTokens(), indicator.type(), indicator.value());
        for (String label : indicator.labels()) {
            tokenHits += tokenHits(profile.indicatorTokens(), label);
        }
        if (tokenHits > 0 || indicator.severity().weight() >= profile.severity().weight()) {
            indicatorMatches++;
            Finding finding = new Finding(name(), profile.severity(), indicator.id(), profile.summary());
            finding.detail("indicatorType", indicator.type());
            finding.detail("indicatorSeverity", indicator.severity());
            finding.detail("tokenHits", tokenHits);
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

    private int tokenHits(Set<String> tokens, String... values) {
        int hits = 0;
        for (String value : values) {
            if (value == null) {
                continue;
            }
            String lower = value.toLowerCase(Locale.ROOT);
            for (String token : tokens) {
                if (lower.contains(token)) {
                    hits++;
                }
            }
        }
        return hits;
    }

    private int tokenHits(Set<String> tokens, String primary, Map<String, String> attributes) {
        int hits = tokenHits(tokens, primary);
        for (Map.Entry<String, String> entry : attributes.entrySet()) {
            hits += tokenHits(tokens, entry.getKey(), entry.getValue());
        }
        return hits;
    }
}
