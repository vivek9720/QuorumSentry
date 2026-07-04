package io.quorumsentry.cli;

import io.quorumsentry.detect.DefaultDetectorRegistryFactory;
import io.quorumsentry.detect.Finding;
import io.quorumsentry.engine.CorrelationPipeline;
import io.quorumsentry.engine.QuarantinePlanner;
import io.quorumsentry.engine.RiskEngine;
import io.quorumsentry.model.EventRecord;
import io.quorumsentry.model.FlowRecord;
import io.quorumsentry.parser.FlowLogParser;
import io.quorumsentry.parser.SyslogParser;
import io.quorumsentry.report.FindingReportWriter;
import io.quorumsentry.report.JsonReportWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public final class QuorumSentryCli {
    private QuorumSentryCli() {}

    public static void main(String[] args) throws Exception {
        if (args.length < 2 || "--help".equals(args[0])) {
            usage();
            return;
        }
        String command = args[0];
        Path input = Path.of(args[1]);
        switch (command) {
            case "archive" -> analyzeArchive(input);
            case "syslog" -> analyzeSyslog(input);
            case "flows" -> analyzeFlows(input);
            default -> {
                System.err.println("unknown command: " + command);
                usage();
                System.exit(2);
            }
        }
    }

    private static void analyzeArchive(Path input) throws IOException {
        byte[] data = Files.readAllBytes(input);
        RiskEngine.RiskReport report = new CorrelationPipeline().evaluateArchive(data);
        QuarantinePlanner.Plan plan = new QuarantinePlanner().plan(List.of());
        System.out.println(new JsonReportWriter().write(report, plan));
    }

    private static void analyzeSyslog(Path input) throws IOException {
        SyslogParser parser = new SyslogParser();
        List<EventRecord> events = new ArrayList<>();
        for (String line : Files.readAllLines(input)) {
            if (!line.isBlank()) {
                events.add(parser.parse(line.getBytes()));
            }
        }
        List<Finding> findings = DefaultDetectorRegistryFactory.create().run(events, List.of(), List.of());
        System.out.println(new FindingReportWriter().markdown(findings));
    }

    private static void analyzeFlows(Path input) throws IOException {
        List<FlowRecord> flows = new FlowLogParser().parse(Files.readAllBytes(input));
        RiskEngine.RiskReport report = new RiskEngine().evaluate(List.of(), flows, List.of(), null);
        QuarantinePlanner.Plan plan = new QuarantinePlanner().plan(flows);
        System.out.println(new JsonReportWriter().write(report, plan));
    }

    private static void usage() {
        System.out.println("Usage: java io.quorumsentry.cli.QuorumSentryCli <archive|syslog|flows> <input-file>");
    }
}
