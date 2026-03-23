#!/usr/bin/env bash
# Build the P2 Chat desktop app using PyInstaller.
# Run from the client/ directory: bash build.sh
#
# Output: dist/P2Chat.exe (Windows) or dist/P2Chat (macOS/Linux)
#
# Requirements:
#   - poetry install (including dev extras that include pyinstaller)
#   - On Windows: WebView2 Runtime (pre-installed on Windows 11)
#   - On macOS:   Xcode Command Line Tools

set -e
cd "$(dirname "$0")"

echo "[build] Installing dependencies..."
poetry install --no-root

echo "[build] Running PyInstaller..."
poetry run pyinstaller \
  --noconfirm \
  --clean \
  --name "P2Chat" \
  --add-data "ui/index.html:ui" \
  --hidden-import "app.crypto.keys" \
  --hidden-import "app.crypto.x3dh" \
  --hidden-import "app.crypto.ratchet" \
  --hidden-import "app.crypto.session" \
  --hidden-import "app.crypto.groups" \
  --collect-all "kyber_py" \
  --collect-all "nacl" \
  --collect-all "webview" \
  --windowed \
  app/main.py

echo "[build] Done. Binary is at: dist/P2Chat"
