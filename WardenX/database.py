import sqlite3
import datetime
from pathlib import Path

def get_db_path():
    return Path.home() / ".wardenx_logs.db"

def init_db():
    conn = sqlite3.connect(get_db_path())
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            file_path TEXT,
            file_hash TEXT,
            scan_engine TEXT,
            verdict TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS block_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            original_path TEXT,
            quarantine_path TEXT,
            threat_signature TEXT,
            file_hash TEXT
        )
    ''')
    conn.commit()
    conn.close()

def log_scan(file_path, file_hash, scan_engine, verdict):
    init_db()
    conn = sqlite3.connect(get_db_path())
    cursor = conn.cursor()
    timestamp = datetime.datetime.now().isoformat()
    cursor.execute('''
        INSERT INTO scan_history (timestamp, file_path, file_hash, scan_engine, verdict)
        VALUES (?, ?, ?, ?, ?)
    ''', (timestamp, str(file_path), file_hash, scan_engine, verdict))
    conn.commit()
    conn.close()

def log_block(original_path, quarantine_path, threat_signature, file_hash):
    init_db()
    conn = sqlite3.connect(get_db_path())
    cursor = conn.cursor()
    timestamp = datetime.datetime.now().isoformat()
    cursor.execute('''
        INSERT INTO block_history (timestamp, original_path, quarantine_path, threat_signature, file_hash)
        VALUES (?, ?, ?, ?, ?)
    ''', (timestamp, str(original_path), str(quarantine_path), threat_signature, file_hash))
    conn.commit()
    conn.close()

def get_recent_scans(limit=10):
    init_db()
    conn = sqlite3.connect(get_db_path())
    cursor = conn.cursor()
    cursor.execute('SELECT timestamp, file_path, file_hash, scan_engine, verdict FROM scan_history ORDER BY id DESC LIMIT ?', (limit,))
    results = cursor.fetchall()
    conn.close()
    return results

def get_recent_blocks(limit=10):
    init_db()
    conn = sqlite3.connect(get_db_path())
    cursor = conn.cursor()
    cursor.execute('SELECT timestamp, original_path, quarantine_path, threat_signature, file_hash FROM block_history ORDER BY id DESC LIMIT ?', (limit,))
    results = cursor.fetchall()
    conn.close()
    return results

def get_stats():
    init_db()
    conn = sqlite3.connect(get_db_path())
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) FROM scan_history')
    total_scans = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM block_history')
    total_blocks = cursor.fetchone()[0]
    conn.close()
    return total_scans, total_blocks

def clear_db():
    init_db()
    conn = sqlite3.connect(get_db_path())
    cursor = conn.cursor()
    cursor.execute('DELETE FROM scan_history')
    cursor.execute('DELETE FROM block_history')
    conn.commit()
    conn.close()
