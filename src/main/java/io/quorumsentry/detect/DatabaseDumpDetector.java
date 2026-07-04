package io.quorumsentry.detect;

import io.quorumsentry.model.Severity;

public final class DatabaseDumpDetector extends ProfiledDetector {
    public DatabaseDumpDetector() {
        super(new DetectorProfile(
                "DatabaseDumpDetector",
                Severity.CRITICAL,
                "Database dump behavior appeared in network or event telemetry.",
                DetectorProfile.tokens("dump", "select", "database", "pg_dump"),
                DetectorProfile.tokens("postgres", "mysql", "elasticsearch"),
                DetectorProfile.tokens("database", "dump"),
                1500000L,
                0L,
                false,
                false));
    }
}
