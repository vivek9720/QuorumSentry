package io.quorumsentry.detect;

import io.quorumsentry.model.Severity;

public final class HoneytokenDetector extends ProfiledDetector {
    public HoneytokenDetector() {
        super(new DetectorProfile(
                "HoneytokenDetector",
                Severity.CRITICAL,
                "Honeytoken string was touched by an actor.",
                DetectorProfile.tokens("honey", "canary", "decoy"),
                DetectorProfile.tokens("http", "dns"),
                DetectorProfile.tokens("honey", "token"),
                0L,
                0L,
                false,
                false));
    }
}
