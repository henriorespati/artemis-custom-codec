#!/usr/bin/env bash
# Generates a new AES-256 key and writes it to /etc/artemis/codec.key
# Usage: bash generate-key.sh [output-path]
set -euo pipefail
JAR="$(dirname "$0")/../target/artemis-custom-codec-1.0.0.jar"
OUT="${1:-/etc/artemis/codec.key}"
java -cp "$JAR" com.example.artemis.codec.CodecTool --generate-key --out "$OUT"
chmod 600 "$OUT"
echo "Key written to $OUT (chmod 600)"
