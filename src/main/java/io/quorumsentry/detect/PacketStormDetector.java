package io.quorumsentry.detect;

import io.quorumsentry.model.Severity;

public final class PacketStormDetector extends ProfiledDetector {
    public PacketStormDetector() {
        super(new DetectorProfile(
                "PacketStormDetector",
                Severity.MEDIUM,
                "Packet count exceeded local storm threshold.",
                DetectorProfile.tokens("storm", "flood"),
                DetectorProfile.tokens("udp", "tcp"),
                DetectorProfile.tokens("ddos", "flood"),
                0L,
                10000L,
                false,
                false));
    }
}
