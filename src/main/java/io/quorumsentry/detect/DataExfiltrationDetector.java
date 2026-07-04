package io.quorumsentry.detect;

import io.quorumsentry.model.Severity;

public final class DataExfiltrationDetector extends ProfiledDetector {
    public DataExfiltrationDetector() {
        super(new DetectorProfile(
                "DataExfiltrationDetector",
                Severity.CRITICAL,
                "Large transfer with exfiltration language observed.",
                DetectorProfile.tokens("exfil", "upload", "staging", "dump"),
                DetectorProfile.tokens("https", "smb", "postgres"),
                DetectorProfile.tokens("exfil", "stager"),
                1000000L,
                0L,
                false,
                false));
    }
}
