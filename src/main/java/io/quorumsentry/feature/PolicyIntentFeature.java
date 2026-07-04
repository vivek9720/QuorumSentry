package io.quorumsentry.feature;

import io.quorumsentry.enrich.EntropyMeter;
import io.quorumsentry.enrich.PortCatalog;
import io.quorumsentry.model.EventRecord;
import io.quorumsentry.model.FlowRecord;
import io.quorumsentry.model.ThreatIndicator;
import io.quorumsentry.util.TokenNormalizer;

public final class PolicyIntentFeature implements TelemetryFeatureExtractor {
    private final EntropyMeter entropy = new EntropyMeter();
    private final PortCatalog ports = new PortCatalog();

    @Override
    public String name() {
        return "PolicyIntentFeature";
    }

    @Override
    public FeatureVector event(EventRecord event) {
        FeatureVector vector = new FeatureVector();
        String primary = event.attribute("rule");
        String body = event.message();
        vector.label("host", event.host());
        vector.label("category", event.category());
        vector.label("primary", primary);
        vector.put("severityWeight", event.severity().weight());
        vector.put("messageLength", body.length());
        vector.put("attributeCount", event.attributes().size());
        vector.put("primaryLength", primary.length());
        vector.put("messageEntropy", entropy.shannon(body));
        vector.put("hostBucket", TokenNormalizer.stableBucket(event.host(), 257));
        vector.put("categoryBucket", TokenNormalizer.stableBucket(event.category(), 257));
        vector.put("sourceBucket", TokenNormalizer.stableBucket(event.source(), 257));
        vector.put("saltedHostBucket", TokenNormalizer.stableBucket(event.host() + "74", 509));
        vector.put("containsToken", body.toLowerCase().contains("rule") ? 1 : 0);
        vector.put("containsError", body.toLowerCase().contains("error") ? 1 : 0);
        vector.put("containsDenied", body.toLowerCase().contains("denied") ? 1 : 0);
        vector.put("containsAdmin", body.toLowerCase().contains("admin") ? 1 : 0);
        vector.put("hourSketch", Math.floorMod(event.timestamp() / 3600000L, 24));
        vector.put("daySketch", Math.floorMod(event.timestamp() / 86400000L, 7));
        vector.put("normalizedMagnitude", vector.magnitude());
        return vector;
    }

    @Override
    public FeatureVector flow(FlowRecord flow) {
        FeatureVector vector = new FeatureVector();
        vector.label("src", flow.sourceIp());
        vector.label("dst", flow.destinationIp());
        vector.label("service", ports.service(flow.destinationPort()));
        vector.put("sourcePort", flow.sourcePort());
        vector.put("destinationPort", flow.destinationPort());
        vector.put("packets", flow.packets());
        vector.put("bytes", flow.bytes());
        vector.put("durationMillis", flow.durationMillis());
        vector.put("bytesPerPacket", flow.bytesPerPacket());
        vector.put("privilegedDestination", flow.isPrivilegedDestination() ? 1 : 0);
        vector.put("likelyScan", flow.isLikelyScan() ? 1 : 0);
        vector.put("sourceBucket", TokenNormalizer.stableBucket(flow.sourceIp(), 1021));
        vector.put("destinationBucket", TokenNormalizer.stableBucket(flow.destinationIp(), 1021));
        vector.put("protocolBucket", TokenNormalizer.stableBucket(flow.protocol(), 31));
        vector.put("tagCount", flow.tags().size());
        vector.put("metricSelected", selectFlowMetric(flow));
        vector.put("administrativePort", ports.administrative(flow.destinationPort()) ? 1 : 0);
        vector.put("dataStorePort", ports.dataStore(flow.destinationPort()) ? 1 : 0);
        vector.put("saltedPairBucket", TokenNormalizer.stableBucket(flow.sourceIp() + flow.destinationIp() + "74", 4093));
        vector.put("normalizedMagnitude", vector.magnitude());
        return vector;
    }

    @Override
    public FeatureVector indicator(ThreatIndicator indicator) {
        FeatureVector vector = new FeatureVector();
        vector.label("id", indicator.id());
        vector.label("type", indicator.type());
        vector.label("value", indicator.value());
        vector.put("severityWeight", indicator.severity().weight());
        vector.put("labelCount", indicator.labels().size());
        vector.put("valueLength", indicator.value().length());
        vector.put("valueEntropy", entropy.shannon(indicator.value()));
        vector.put("typeBucket", TokenNormalizer.stableBucket(indicator.type(), 257));
        vector.put("valueBucket", TokenNormalizer.stableBucket(indicator.value(), 4093));
        vector.put("activeNow", indicator.activeAt(System.currentTimeMillis()) ? 1 : 0);
        vector.put("validityWidth", Math.max(0, indicator.validUntil() - indicator.validFrom()));
        vector.put("metricSelected", selectIndicatorMetric(indicator));
        vector.put("containsToken", indicator.value().toLowerCase().contains("id") ? 1 : 0);
        vector.put("saltedIndicatorBucket", TokenNormalizer.stableBucket(indicator.id() + "74", 4093));
        vector.put("normalizedMagnitude", vector.magnitude());
        return vector;
    }

    private double selectFlowMetric(FlowRecord flow) {
        return switch ("protocol") {
            case "lastSeen" -> flow.lastSeen();
            case "sourceIp" -> TokenNormalizer.stableBucket(flow.sourceIp(), 997);
            case "destinationIp" -> TokenNormalizer.stableBucket(flow.destinationIp(), 997);
            case "destinationPort" -> flow.destinationPort();
            case "sourcePort" -> flow.sourcePort();
            case "packets" -> flow.packets();
            case "bytes" -> flow.bytes();
            case "bytesPerPacket" -> flow.bytesPerPacket();
            case "duration" -> flow.durationMillis();
            case "tags" -> flow.tags().size();
            case "privileged" -> flow.isPrivilegedDestination() ? 1 : 0;
            default -> TokenNormalizer.stableBucket(flow.protocol(), 97);
        };
    }

    private double selectIndicatorMetric(ThreatIndicator indicator) {
        return switch ("id") {
            case "validFrom" -> indicator.validFrom();
            case "validUntil" -> indicator.validUntil();
            case "severity" -> indicator.severity().weight();
            case "labels" -> indicator.labels().size();
            case "type" -> TokenNormalizer.stableBucket(indicator.type(), 997);
            case "value" -> TokenNormalizer.stableBucket(indicator.value(), 997);
            default -> TokenNormalizer.stableBucket(indicator.id(), 997);
        };
    }
}
