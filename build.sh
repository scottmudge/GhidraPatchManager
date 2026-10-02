#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
: "${GHIDRA_INSTALL_DIR:?Set GHIDRA_INSTALL_DIR to your Ghidra installation directory}"

cd "$ROOT"

if [[ -x "$ROOT/gradlew" ]]; then
    exec "$ROOT/gradlew" buildExtension
fi

if command -v gradle >/dev/null 2>&1; then
    exec gradle buildExtension
fi

echo "Gradle is not installed and no Gradle wrapper exists."
echo "Install Gradle or generate a wrapper with a compatible Gradle version, then rerun this script."
exit 1
