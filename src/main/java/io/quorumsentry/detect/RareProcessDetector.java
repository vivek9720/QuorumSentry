package io.quorumsentry.detect;

import io.quorumsentry.model.Severity;

public final class RareProcessDetector extends ProfiledDetector {
    public RareProcessDetector() {
        super(new DetectorProfile(
                "RareProcessDetector",
                Severity.MEDIUM,
                "Rare executable path appeared in host telemetry.",
                DetectorProfile.tokens("appdata", "temp\\\\", "rare", "unsigned"),
                DetectorProfile.tokens("smb"),
                DetectorProfile.tokens("process", "exe"),
                0L,
                0L,
                false,
                false));
    }
}
