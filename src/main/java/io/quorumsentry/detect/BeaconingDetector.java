package io.quorumsentry.detect;

import io.quorumsentry.model.Severity;

public final class BeaconingDetector extends ProfiledDetector {
    public BeaconingDetector() {
        super(new DetectorProfile(
                "BeaconingDetector",
                Severity.MEDIUM,
                "Periodic low-volume traffic can indicate command-and-control.",
                DetectorProfile.tokens("beacon", "callback", "heartbeat"),
                DetectorProfile.tokens("beacon", "http", "https"),
                DetectorProfile.tokens("c2", "beacon", "implant"),
                50000L,
                0L,
                false,
                false));
    }
}
