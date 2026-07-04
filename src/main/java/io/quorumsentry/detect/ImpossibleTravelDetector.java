package io.quorumsentry.detect;

import io.quorumsentry.model.Severity;

public final class ImpossibleTravelDetector extends ProfiledDetector {
    public ImpossibleTravelDetector() {
        super(new DetectorProfile(
                "ImpossibleTravelDetector",
                Severity.MEDIUM,
                "User geography changed too quickly for normal travel.",
                DetectorProfile.tokens("geo", "travel", "country"),
                DetectorProfile.tokens("vpn"),
                DetectorProfile.tokens("geo", "identity"),
                0L,
                0L,
                false,
                false));
    }
}
