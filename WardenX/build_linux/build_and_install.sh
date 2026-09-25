#!/bin/bash
set -e

echo "Starting Linux Build and Install for WardenX..."

# Install PyInstaller
pip install pyinstaller --break-system-packages

# Build binary
pyinstaller --name WardenX --onefile --add-data "rules/malware.yar:rules" tray_app.py

echo "Moving binary to /usr/local/bin/wardenx..."
sudo mv dist/WardenX /usr/local/bin/wardenx
sudo chmod +x /usr/local/bin/wardenx

echo "Generating systemd service..."
sudo tee /etc/systemd/system/wardenx.service > /dev/null <<EOF
[Unit]
Description=WardenX EDR Daemon
After=network.target

[Service]
ExecStart=/usr/local/bin/wardenx
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

echo "Enabling and starting systemd service..."
sudo systemctl daemon-reload
sudo systemctl enable wardenx.service
sudo systemctl start wardenx.service

echo "WardenX successfully installed and started."
