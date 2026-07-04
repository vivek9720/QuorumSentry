package io.quorumsentry.detect;

import io.quorumsentry.model.Severity;

public final class LateralMovementDetector extends ProfiledDetector {
    public LateralMovementDetector() {
        super(new DetectorProfile(
                "LateralMovementDetector",
                Severity.HIGH,
                "Remote execution tooling appeared in event text.",
                DetectorProfile.tokens("psexec", "wmic", "winrm", "remote"),
                DetectorProfile.tokens("smb", "rdp", "ldap"),
                DetectorProfile.tokens("lateral", "movement"),
                0L,
                0L,
                true,
                true));
    }
}
