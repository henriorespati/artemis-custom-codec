#!/usr/bin/env bash
# Masks a plaintext password using the AES-256-GCM codec.
# Usage: bash mask-password.sh --password <value> [--key-location <path>]
set -euo pipefail
JAR="$(dirname "$0")/../target/artemis-custom-codec-1.0.0.jar"
java -cp "$JAR" com.example.artemis.codec.CodecTool --mask "$@"
