package io.quorumsentry.detect;

import io.quorumsentry.model.Severity;

public final class LongSessionDetector extends ProfiledDetector {
    public LongSessionDetector() {
        super(new DetectorProfile(
                "LongSessionDetector",
                Severity.LOW,
                "Long-lived session merits analyst review.",
                DetectorProfile.tokens("session", "long"),
                DetectorProfile.tokens("ssh", "https"),
                DetectorProfile.tokens("session"),
                0L,
                0L,
                false,
                false));
    }
}
