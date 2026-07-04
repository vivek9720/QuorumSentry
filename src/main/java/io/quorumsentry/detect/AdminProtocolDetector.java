package io.quorumsentry.detect;

import io.quorumsentry.model.Severity;

public final class AdminProtocolDetector extends ProfiledDetector {
    public AdminProtocolDetector() {
        super(new DetectorProfile(
                "AdminProtocolDetector",
                Severity.HIGH,
                "Administrative protocol used in a suspicious context.",
                DetectorProfile.tokens("rdp", "ssh", "winrm"),
                DetectorProfile.tokens("ssh", "rdp"),
                DetectorProfile.tokens("admin", "remote"),
                0L,
                0L,
                false,
                true));
    }
}
