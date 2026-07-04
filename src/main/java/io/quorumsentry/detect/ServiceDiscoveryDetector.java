package io.quorumsentry.detect;

import io.quorumsentry.model.Severity;

public final class ServiceDiscoveryDetector extends ProfiledDetector {
    public ServiceDiscoveryDetector() {
        super(new DetectorProfile(
                "ServiceDiscoveryDetector",
                Severity.MEDIUM,
                "Low-packet privileged flow suggests service discovery.",
                DetectorProfile.tokens("scan", "probe", "discover"),
                DetectorProfile.tokens("ssh", "http", "ldap", "smb"),
                DetectorProfile.tokens("scan", "recon"),
                0L,
                0L,
                true,
                false));
    }
}
