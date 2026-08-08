#!/usr/bin/env bash
# Build the cscli beacon into a standalone executable with PyInstaller.
#
# Usage:
#   ./scripts/build-binary.sh [linux64|windows64|windows32]
#
# NOTE ON CROSS-COMPILATION:
#   PyInstaller does NOT cross-compile. A binary built on this host matches this
#   host's OS/architecture only.
#     * On Linux aarch64/x86_64 == Linux ELF beacon.
#     * To produce a Windows .exe (64-bit or 32-bit), run this same command on a
#       Windows machine with Python 3.8+ installed, selecting the matching
#       PyInstaller; you will get a native .exe. The result is what the PE
#       loader chains (loader.ps1) expect.
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HERE"
TARGET="${1:-linux64}"
NAME="cscli-beacon"

PY="python3"
case "$TARGET" in
  linux64) extra=() ;;
  windows64) extra=("--target-arch=x86_64") ;;
  windows32) extra=("--target-arch=x86") ;;
  *) echo "unknown target: $TARGET"; exit 1 ;;
esac

# Use a scratch build dir so build/beacon_entry.py stays a tracked source file.
rm -rf "$HERE/build/_pyi"
"$PY" -m PyInstaller --onefile --clean \
    --distpath "$HERE/dist" \
    --workpath "$HERE/build/_pyi" \
    --specpath "$HERE/build" \
    --name "$NAME" \
    "${extra[@]}" \
    "$HERE/build/beacon_entry.py"

echo
echo "[+] built: $HERE/dist/$NAME"
file "$HERE/dist/$NAME" 2>/dev/null || true
