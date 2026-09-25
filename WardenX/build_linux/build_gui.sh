#!/usr/bin/env bash
set -e

echo "==================================================="
echo "       WardenX GUI - Linux Build Script"
echo "==================================================="
echo ""

# Navigate to project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

echo "[1/4] Installing/verifying build dependencies..."
pip install pyinstaller customtkinter --break-system-packages || pip install pyinstaller customtkinter

echo ""
echo "[2/4] Building standalone WardenX_UI binary..."
pyinstaller --name WardenX_UI --onefile --windowed --collect-all customtkinter --add-data "rules/malware.yar:rules" gui_app.py

echo ""
echo "[3/4] Moving binary to build_linux directory..."
mkdir -p build_linux
if [ -f "dist/WardenX_UI" ]; then
    mv -f dist/WardenX_UI build_linux/WardenX_UI
    chmod +x build_linux/WardenX_UI
    echo "[SUCCESS] Binary moved to build_linux/WardenX_UI"
else
    echo "[ERROR] dist/WardenX_UI not found."
    exit 1
fi

echo ""
echo "[4/4] Creating desktop shortcut (WardenX.desktop)..."
DESKTOP_DIR="$HOME/.local/share/applications"
mkdir -p "$DESKTOP_DIR"

BINARY_PATH="$(pwd)/build_linux/WardenX_UI"

cat <<EOF > "$DESKTOP_DIR/WardenX.desktop"
[Desktop Entry]
Version=1.0
Type=Application
Name=WardenX Security Center
Comment=Lightweight Endpoint Detection and Response (EDR) Security Dashboard
Exec=$BINARY_PATH
Icon=security-high
Terminal=false
Categories=Utility;Security;System;
StartupNotify=true
EOF

chmod +x "$DESKTOP_DIR/WardenX.desktop"
echo "[SUCCESS] Desktop entry created at $DESKTOP_DIR/WardenX.desktop"

echo ""
echo "==================================================="
echo "   Build Successful: build_linux/WardenX_UI"
echo "==================================================="
