package io.quorumsentry.detect;

import io.quorumsentry.model.Severity;

public final class PolicyBypassDetector extends ProfiledDetector {
    public PolicyBypassDetector() {
        super(new DetectorProfile(
                "PolicyBypassDetector",
                Severity.HIGH,
                "Policy bypass language appeared in rule or event data.",
                DetectorProfile.tokens("bypass", "disable", "allowlist"),
                DetectorProfile.tokens("http"),
                DetectorProfile.tokens("bypass", "policy"),
                0L,
                0L,
                false,
                false));
    }
}
