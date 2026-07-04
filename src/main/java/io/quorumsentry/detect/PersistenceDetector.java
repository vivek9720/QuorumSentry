package io.quorumsentry.detect;

import io.quorumsentry.model.Severity;

public final class PersistenceDetector extends ProfiledDetector {
    public PersistenceDetector() {
        super(new DetectorProfile(
                "PersistenceDetector",
                Severity.HIGH,
                "Persistence artifact appeared in telemetry.",
                DetectorProfile.tokens("runkey", "startup", "service", "cron"),
                DetectorProfile.tokens("smb", "ssh"),
                DetectorProfile.tokens("persistence", "runkey"),
                0L,
                0L,
                false,
                true));
    }
}
