package io.quorumsentry.detect;

import io.quorumsentry.model.Severity;

public final class SuspiciousUserAgentDetector extends ProfiledDetector {
    public SuspiciousUserAgentDetector() {
        super(new DetectorProfile(
                "SuspiciousUserAgentDetector",
                Severity.MEDIUM,
                "Unusual user-agent indicator appeared in telemetry.",
                DetectorProfile.tokens("user_agent", "curl", "python-requests"),
                DetectorProfile.tokens("http", "https"),
                DetectorProfile.tokens("user_agent"),
                0L,
                0L,
                false,
                false));
    }
}
