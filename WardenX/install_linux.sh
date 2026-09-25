#!/usr/bin/env bash
set -e

echo "==================================================="
echo "        WardenX EDR - Linux Installation"
echo "==================================================="
echo ""

echo "[1/3] Creating virtual environment (venv)..."
python3 -m venv venv

echo ""
echo "[2/3] Activating virtual environment & installing dependencies..."
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

echo ""
echo "[3/3] Installing WardenX package..."
python setup.py install

echo ""
echo "==================================================="
echo "        Installation Completed Successfully!"
echo "==================================================="
echo ""
echo "To launch the WardenX Security Center GUI Dashboard:"
echo "    source venv/bin/activate && python gui_app.py"
echo "  or directly:"
echo "    venv/bin/python gui_app.py"
echo ""
echo "To run CLI commands:"
echo "    venv/bin/wardenx --help"
echo ""
