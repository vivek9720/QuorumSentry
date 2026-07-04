# QuorumSentry

QuorumSentry is a JVM security telemetry correlator for small response teams that need to triage heterogeneous evidence without deploying a service. It parses syslog, flow CSV, compact threat bundles, policy rules, and a small archive format, then builds an incident graph and risk report.

It is designed for offline incident review in lab networks, air-gapped response rooms, and small environments where telemetry needs to be exchanged as files instead of streamed into a central SaaS platform. The core library is dependency-light so responders can build it from a clean checkout and run the parsers, graphing, feature extraction, and policy evaluation locally.

## Formats

- Syslog lines with key-value enrichment.
- Flow CSV rows: `src,dst,sport,dport,proto,packets,bytes,first,last[,dnsSketch]`.
- QTI binary threat bundles with typed indicators and labels.
- Policy DSL statements such as `rule ssh when dport == 22 then quarantine target=host`.
- QAR archives that combine multiple telemetry objects.

## Offline Analysis

QuorumSentry can be used as a library or as a small command-line analyzer:

```bash
java io.quorumsentry.cli.QuorumSentryCli syslog incident.log
java io.quorumsentry.cli.QuorumSentryCli flows netflow.csv
java io.quorumsentry.cli.QuorumSentryCli archive case.qar
```

The analyzer emits JSON risk summaries for structured inputs and Markdown findings for syslog review. Detectors cover credential abuse, administrative protocol exposure, DNS tunneling, data exfiltration, ransomware preparation, persistence, identity-provider misuse, and related incident-response signals.

## Local Build

```bash
javac -d build/classes $(find src/main/java -name '*.java')
```

The `fuzz/` directory contains parser harnesses used during development to harden the file formats and policy DSL.
