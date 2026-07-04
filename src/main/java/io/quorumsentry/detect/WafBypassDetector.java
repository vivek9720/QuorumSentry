package io.quorumsentry.detect;

import io.quorumsentry.model.Severity;

public final class WafBypassDetector extends ProfiledDetector {
    public WafBypassDetector() {
        super(new DetectorProfile(
                "WafBypassDetector",
                Severity.HIGH,
                "Web application firewall bypass wording appeared.",
                DetectorProfile.tokens("waf", "bypass", "sqlmap"),
                DetectorProfile.tokens("http", "https"),
                DetectorProfile.tokens("waf", "bypass"),
                0L,
                0L,
                false,
                false));
    }
}
