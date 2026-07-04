package io.quorumsentry.detect;

import io.quorumsentry.model.Severity;

public final class SinkholeDetector extends ProfiledDetector {
    public SinkholeDetector() {
        super(new DetectorProfile(
                "SinkholeDetector",
                Severity.MEDIUM,
                "Sinkhole routing or DNS evidence was observed.",
                DetectorProfile.tokens("sinkhole", "redirect"),
                DetectorProfile.tokens("dns", "http"),
                DetectorProfile.tokens("sinkhole"),
                0L,
                0L,
                false,
                false));
    }
}
