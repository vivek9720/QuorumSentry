package io.quorumsentry.detect;

import io.quorumsentry.model.Severity;

public final class CredentialSprayDetector extends ProfiledDetector {
    public CredentialSprayDetector() {
        super(new DetectorProfile(
                "CredentialSprayDetector",
                Severity.HIGH,
                "Repeated authentication failures indicate credential spraying.",
                DetectorProfile.tokens("failed", "spray", "password", "locked"),
                DetectorProfile.tokens("ssh", "ldap", "kerberos"),
                DetectorProfile.tokens("credential", "password", "account"),
                0L,
                120L,
                false,
                true));
    }
}
