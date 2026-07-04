package io.quorumsentry.detect;

import io.quorumsentry.model.Severity;

public final class RansomwarePrepDetector extends ProfiledDetector {
    public RansomwarePrepDetector() {
        super(new DetectorProfile(
                "RansomwarePrepDetector",
                Severity.CRITICAL,
                "Backup deletion behavior resembles ransomware preparation.",
                DetectorProfile.tokens("shadowcopy", "vssadmin", "backup", "delete"),
                DetectorProfile.tokens("smb"),
                DetectorProfile.tokens("ransomware", "wiper"),
                500000L,
                0L,
                false,
                true));
    }
}
