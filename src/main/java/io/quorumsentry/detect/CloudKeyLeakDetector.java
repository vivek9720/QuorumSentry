package io.quorumsentry.detect;

import io.quorumsentry.model.Severity;

public final class CloudKeyLeakDetector extends ProfiledDetector {
    public CloudKeyLeakDetector() {
        super(new DetectorProfile(
                "CloudKeyLeakDetector",
                Severity.CRITICAL,
                "Cloud access key material appeared in logs.",
                DetectorProfile.tokens("akia", "secret_access_key", "token"),
                DetectorProfile.tokens("https"),
                DetectorProfile.tokens("cloud", "key", "credential"),
                0L,
                0L,
                false,
                false));
    }
}
