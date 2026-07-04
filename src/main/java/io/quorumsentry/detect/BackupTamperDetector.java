package io.quorumsentry.detect;

import io.quorumsentry.model.Severity;

public final class BackupTamperDetector extends ProfiledDetector {
    public BackupTamperDetector() {
        super(new DetectorProfile(
                "BackupTamperDetector",
                Severity.CRITICAL,
                "Backup tamper wording appeared in telemetry.",
                DetectorProfile.tokens("backup", "tamper", "delete", "snapshot"),
                DetectorProfile.tokens("smb", "ssh"),
                DetectorProfile.tokens("backup", "tamper"),
                0L,
                0L,
                false,
                true));
    }
}
