package io.quorumsentry.detect;

import io.quorumsentry.model.Severity;

public final class IdentityGraphDetector extends ProfiledDetector {
    public IdentityGraphDetector() {
        super(new DetectorProfile(
                "IdentityGraphDetector",
                Severity.HIGH,
                "Identity federation artifacts showed suspicious use.",
                DetectorProfile.tokens("saml", "oauth", "assertion", "mfa"),
                DetectorProfile.tokens("https", "ldap"),
                DetectorProfile.tokens("identity", "saml"),
                0L,
                0L,
                false,
                false));
    }
}
