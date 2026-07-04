package io.quorumsentry.detect;

import io.quorumsentry.model.Severity;

public final class TorExitDetector extends ProfiledDetector {
    public TorExitDetector() {
        super(new DetectorProfile(
                "TorExitDetector",
                Severity.MEDIUM,
                "Known anonymity infrastructure touched monitored systems.",
                DetectorProfile.tokens("tor", "onion", "proxy"),
                DetectorProfile.tokens("tor", "https"),
                DetectorProfile.tokens("tor", "exit"),
                0L,
                0L,
                false,
                false));
    }
}
