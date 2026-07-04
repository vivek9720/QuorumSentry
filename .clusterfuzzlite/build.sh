#!/bin/bash -eu
cd "${SRC:-$(pwd)}"
BUILD_DIR="$WORK/quorumsentry-classes"
LIB_DIR="$OUT/.quorumsentry-lib"
mkdir -p "$BUILD_DIR" "$OUT" "$LIB_DIR"
find src/main/java fuzz -name '*.java' | sort > "$WORK/quorumsentry-sources.txt"

JAZZER_API="${JAZZER_API_PATH:-}"
if [[ -z "$JAZZER_API" || ! -f "$JAZZER_API" ]]; then
  JAZZER_API="$(find /usr/local /opt -name jazzer_api_deploy.jar -type f 2>/dev/null | head -n 1 || true)"
fi

if [[ -n "$JAZZER_API" ]]; then
  javac -encoding UTF-8 -g -cp "$JAZZER_API" -d "$BUILD_DIR" @"$WORK/quorumsentry-sources.txt"
  cp "$JAZZER_API" "$LIB_DIR/jazzer_api_deploy.jar"
else
  javac -encoding UTF-8 -g -d "$BUILD_DIR" @"$WORK/quorumsentry-sources.txt"
fi

jar cf "$LIB_DIR/quorumsentry.jar" -C "$BUILD_DIR" .
find /usr/local /opt -name 'jazzer*standalone*.jar' -type f 2>/dev/null \
  -exec cp {} "$LIB_DIR/" \; || true

emit_jazzer_wrapper() {
  local target="$1"
  local output="$OUT/$target"
  cat > "$output" <<EOF
#!/bin/bash
set -eu
DIR="\$(cd "\$(dirname "\$0")" && pwd)"
LIB_DIR="\$DIR/.quorumsentry-lib"
CP="\$LIB_DIR/quorumsentry.jar"
if [[ -f "\$LIB_DIR/jazzer_api_deploy.jar" ]]; then
  CP="\$CP:\$LIB_DIR/jazzer_api_deploy.jar"
fi
JAZZER_BIN="\${JAZZER:-}"
if [[ -z "\$JAZZER_BIN" ]]; then
  for candidate in /usr/local/bin/jazzer /usr/bin/jazzer /opt/jazzer/jazzer; do
    if [[ -x "\$candidate" ]]; then
      JAZZER_BIN="\$candidate"
      break
    fi
  done
fi
if [[ -z "\$JAZZER_BIN" ]]; then
  for jar in "\$LIB_DIR"/jazzer*standalone*.jar; do
    if [[ -f "\$jar" && "\$jar" != *jazzer_api_deploy.jar ]]; then
      exec java -jar "\$jar" --cp="\$CP" --target_class="$target" "\$@"
    fi
  done
  echo "jazzer launcher or standalone jar not found in runtime image" >&2
  exit 127
fi
exec "\$JAZZER_BIN" --cp="\$CP" --target_class="$target" "\$@"
EOF
  chmod +x "$output"
}

for target in SyslogFuzzer FlowFuzzer ThreatBundleFuzzer PolicyFuzzer ArchiveFuzzer; do
  if command -v compile_jvm_fuzzer >/dev/null 2>&1; then
    compile_jvm_fuzzer "$LIB_DIR/quorumsentry.jar" "$target" "$OUT/$target"
  else
    emit_jazzer_wrapper "$target"
  fi
done
