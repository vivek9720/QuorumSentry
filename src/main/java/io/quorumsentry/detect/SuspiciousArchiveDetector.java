package io.quorumsentry.detect;

import io.quorumsentry.model.Severity;

public final class SuspiciousArchiveDetector extends ProfiledDetector {
    public SuspiciousArchiveDetector() {
        super(new DetectorProfile(
                "SuspiciousArchiveDetector",
                Severity.MEDIUM,
                "Archive handling activity has suspicious indicators.",
                DetectorProfile.tokens("archive", "zip", "qar", "extract"),
                DetectorProfile.tokens("http", "smb"),
                DetectorProfile.tokens("archive", "packed"),
                250000L,
                0L,
                false,
                false));
    }
}
