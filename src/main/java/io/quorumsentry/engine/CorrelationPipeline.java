package io.quorumsentry.engine;

import io.quorumsentry.model.EventRecord;
import io.quorumsentry.parser.ArchiveParser;
import io.quorumsentry.parser.FlowLogParser;
import io.quorumsentry.parser.PolicyParser;
import io.quorumsentry.parser.SyslogParser;
import io.quorumsentry.parser.ThreatBundleParser;
import io.quorumsentry.policy.Policy;
import java.util.ArrayList;
import java.util.List;

public final class CorrelationPipeline {
    private final SyslogParser syslogParser = new SyslogParser();
    private final FlowLogParser flowLogParser = new FlowLogParser();
    private final ThreatBundleParser threatBundleParser = new ThreatBundleParser();
    private final PolicyParser policyParser = new PolicyParser();
    private final ArchiveParser archiveParser = new ArchiveParser();
    private final RiskEngine riskEngine = new RiskEngine();

    public RiskEngine.RiskReport evaluateArchive(byte[] archiveBytes) {
        TelemetryBatch batch = new TelemetryBatch();
        Policy policy = null;
        List<ArchiveParser.ArchiveRecord> records = archiveParser.parse(archiveBytes);
        for (ArchiveParser.ArchiveRecord record : records) {
            switch (record.type()) {
                case 1 -> batch.events().add(syslogParser.parse(record.payload()));
                case 2 -> batch.flows().addAll(flowLogParser.parse(record.payload()));
                case 3 -> batch.indicators().addAll(threatBundleParser.parse(record.payload()));
                case 4 -> policy = policyParser.parse(record.payload());
                default -> {
                    if (record.name().endsWith(".log")) {
                        batch.events().add(syslogParser.parse(record.payload()));
                    }
                }
            }
        }
        return riskEngine.evaluate(batch.events(), batch.flows(), batch.indicators(), policy);
    }

    public List<EventRecord> parseLooseEvents(byte[] text) {
        List<EventRecord> events = new ArrayList<>();
        String payload = new String(text == null ? new byte[0] : text);
        for (String line : payload.split("\\r?\\n")) {
            if (!line.isBlank()) {
                events.add(syslogParser.parse(line.getBytes()));
            }
        }
        return events;
    }
}
