import pytest
from database import init_db, log_scan, log_block, get_recent_scans, get_recent_blocks
import sqlite3

def test_init_db(mock_db_path):
    init_db()
    conn = sqlite3.connect(mock_db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = [row[0] for row in cursor.fetchall()]
    assert "scan_history" in tables
    assert "block_history" in tables
    conn.close()

def test_log_scan(mock_db_path):
    log_scan("/fake/path.exe", "fakehash", "Yara", "Malicious")
    scans = get_recent_scans()
    assert len(scans) == 1
    assert scans[0][1] == "/fake/path.exe"
    assert scans[0][2] == "fakehash"
    assert scans[0][3] == "Yara"
    assert scans[0][4] == "Malicious"

def test_log_block(mock_db_path):
    log_block("/original/path.exe", "/quarantine/path.exe", "Threat1", "fakehash")
    blocks = get_recent_blocks()
    assert len(blocks) == 1
    assert blocks[0][1] == "/original/path.exe"
    assert blocks[0][2] == "/quarantine/path.exe"
    assert blocks[0][3] == "Threat1"
    assert blocks[0][4] == "fakehash"
