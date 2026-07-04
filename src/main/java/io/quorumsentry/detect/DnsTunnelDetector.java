package io.quorumsentry.detect;

import io.quorumsentry.model.Severity;

public final class DnsTunnelDetector extends ProfiledDetector {
    public DnsTunnelDetector() {
        super(new DetectorProfile(
                "DnsTunnelDetector",
                Severity.HIGH,
                "DNS label sketches suggest tunneling behavior.",
                DetectorProfile.tokens("dns", "tunnel"),
                DetectorProfile.tokens("dns", "dns_tunnel_hint"),
                DetectorProfile.tokens("dns", "tunnel"),
                250000L,
                0L,
                false,
                false));
    }
}
