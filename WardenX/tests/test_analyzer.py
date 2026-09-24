import pytest
from unittest.mock import patch, mock_open
from analyzer import analyze_file, calculate_sha256, check_virustotal

EICAR_STRING = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

@patch('analyzer.log_scan')
@patch('analyzer.scan_with_yara', return_value=(True, "DummyMalware"))
def test_analyzer_yara_malicious(mock_yara, mock_log, mocker):
    mocker.patch('builtins.open', mock_open(read_data=EICAR_STRING.encode('utf-8')))
    is_malicious, signature = analyze_file("dummy_file.txt")
    
    assert is_malicious is True
    assert signature == "DummyMalware"
    mock_log.assert_called_once_with("dummy_file.txt", EICAR_SHA256, "Yara", "Malicious")

@patch('analyzer.log_scan')
@patch('analyzer.scan_with_yara', return_value=(False, None))
@patch('analyzer.check_virustotal', return_value=True)
def test_analyzer_vt_malicious(mock_vt, mock_yara, mock_log, mocker):
    mocker.patch('builtins.open', mock_open(read_data=EICAR_STRING.encode('utf-8')))
    is_malicious, signature = analyze_file("dummy_file.txt")
    
    assert is_malicious is True
    assert signature == "VirusTotal Detection"
    mock_log.assert_called_once_with("dummy_file.txt", EICAR_SHA256, "VirusTotal", "Malicious")

@patch('analyzer.log_scan')
@patch('analyzer.scan_with_yara', return_value=(False, None))
@patch('analyzer.check_virustotal', return_value=False)
def test_analyzer_benign(mock_vt, mock_yara, mock_log, mocker):
    mocker.patch('builtins.open', mock_open(read_data=b"benign content"))
    is_malicious, signature = analyze_file("dummy_file.txt")
    
    assert is_malicious is False
    assert signature is None
    import hashlib
    h = hashlib.sha256(b"benign content").hexdigest()
    mock_log.assert_called_once_with("dummy_file.txt", h, "All", "Benign")
