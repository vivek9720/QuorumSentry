package io.quorumsentry;

import io.quorumsentry.engine.CorrelationPipeline;
import io.quorumsentry.engine.RiskEngine;
import io.quorumsentry.parser.FlowLogParser;
import io.quorumsentry.parser.PolicyParser;
import io.quorumsentry.parser.SyslogParser;
import io.quorumsentry.parser.ThreatBundleParser;

public final class QuorumSentry {
    private QuorumSentry() {}

    public static RiskEngine.RiskReport evaluateArchive(byte[] data) {
        return new CorrelationPipeline().evaluateArchive(data);
    }

    public static int parseSyslog(byte[] data) {
        return new SyslogParser().parse(data).severity().weight();
    }

    public static int parseFlows(byte[] data) {
        return new FlowLogParser().parse(data).size();
    }

    public static int parseBundle(byte[] data) {
        return new ThreatBundleParser().parse(data).size();
    }

    public static int parsePolicy(byte[] data) {
        return new PolicyParser().parse(data).rules().size();
    }
}
