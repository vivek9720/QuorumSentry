package io.quorumsentry.detect;

import io.quorumsentry.model.Severity;

public final class PayloadEntropyDetector extends ProfiledDetector {
    public PayloadEntropyDetector() {
        super(new DetectorProfile(
                "PayloadEntropyDetector",
                Severity.HIGH,
                "High entropy token may be packed payload or secret.",
                DetectorProfile.tokens("payload", "base64", "compressed"),
                DetectorProfile.tokens("https", "dns"),
                DetectorProfile.tokens("payload", "packed"),
                350000L,
                0L,
                false,
                false));
    }
}
