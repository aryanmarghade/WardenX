import os
import pytest
from unittest.mock import patch
from scanner import scan_directory

def test_scan_directory_nonexistent():
    res = scan_directory("nonexistent_directory_12345")
    assert res["scanned"] == 0
    assert res["errors"] == 1

def test_scan_directory_with_files(tmp_path):
    f1 = tmp_path / "clean.txt"
    f1.write_text("hello clean file")
    
    f2 = tmp_path / "clean2.txt"
    f2.write_text("another clean file")
    
    with patch("scanner.analyze_file", return_value=(False, None)):
        res = scan_directory(str(tmp_path))
        assert res["scanned"] == 2
        assert res["malicious"] == 0
        assert len(res["threats"]) == 0

def test_scan_directory_with_threats(tmp_path):
    threat_file = tmp_path / "virus.exe"
    threat_file.write_text("malicious payload")
    
    with patch("scanner.analyze_file", return_value=(True, "TestMalwareSignature")):
        res = scan_directory(str(tmp_path))
        assert res["scanned"] == 1
        assert res["malicious"] == 1
        assert res["threats"][0]["signature"] == "TestMalwareSignature"
