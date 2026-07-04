# QuorumSentry

QuorumSentry is a JVM security telemetry correlator for small response teams that need to triage heterogeneous evidence without deploying a service. It parses syslog, flow CSV, compact threat bundles, policy rules, and a small archive format, then builds an incident graph and risk report.

The repository is intentionally self-contained for fuzzing submission: no network services, no generated credentials, and no build-time downloads. Fuzz targets are in `fuzz/`; ClusterFuzzLite entry points are in `.clusterfuzzlite/`.

## Formats

- Syslog lines with key-value enrichment.
- Flow CSV rows: `src,dst,sport,dport,proto,packets,bytes,first,last[,dnsSketch]`.
- QTI binary threat bundles with typed indicators and labels.
- Policy DSL statements such as `rule ssh when dport == 22 then quarantine target=host`.
- QAR archives that combine multiple telemetry objects.

## Local Build

```bash
javac -d build/classes $(find src/main/java -name '*.java')
```

For fuzzing, run `.clusterfuzzlite/build.sh` inside the ClusterFuzzLite JVM image.
