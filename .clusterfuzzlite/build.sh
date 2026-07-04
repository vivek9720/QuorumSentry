#!/bin/bash -eu
cd "${SRC:-$(pwd)}"
BUILD_DIR="$WORK/quorumsentry-classes"
mkdir -p "$BUILD_DIR" "$OUT"
find src/main/java fuzz -name '*.java' | sort > "$WORK/quorumsentry-sources.txt"
javac -encoding UTF-8 -g -cp "${JAZZER_API_PATH:-}" -d "$BUILD_DIR" @"$WORK/quorumsentry-sources.txt"
jar cf "$WORK/quorumsentry.jar" -C "$BUILD_DIR" .
for target in SyslogFuzzer FlowFuzzer ThreatBundleFuzzer PolicyFuzzer ArchiveFuzzer; do
  compile_jvm_fuzzer "$WORK/quorumsentry.jar" "$target" "$OUT/$target"
done
