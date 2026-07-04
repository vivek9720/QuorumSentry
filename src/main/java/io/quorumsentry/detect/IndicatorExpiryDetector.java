package io.quorumsentry.detect;

import io.quorumsentry.model.Severity;

public final class IndicatorExpiryDetector extends ProfiledDetector {
    public IndicatorExpiryDetector() {
        super(new DetectorProfile(
                "IndicatorExpiryDetector",
                Severity.LOW,
                "Threat indicator contains an unusual validity window.",
                DetectorProfile.tokens("expired", "stale"),
                DetectorProfile.tokens("http"),
                DetectorProfile.tokens("expired", "stale"),
                0L,
                0L,
                false,
                false));
    }
}
