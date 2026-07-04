package io.quorumsentry.detect;

import io.quorumsentry.model.Severity;

public final class PrivilegeEscalationDetector extends ProfiledDetector {
    public PrivilegeEscalationDetector() {
        super(new DetectorProfile(
                "PrivilegeEscalationDetector",
                Severity.HIGH,
                "Privilege escalation terms appeared in telemetry.",
                DetectorProfile.tokens("sudo", "privilege", "token", "uac"),
                DetectorProfile.tokens("ssh", "rdp"),
                DetectorProfile.tokens("privilege", "exploit"),
                0L,
                0L,
                false,
                true));
    }
}
