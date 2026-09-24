import pytest
from unittest.mock import patch
from enforcer import quarantine_file, alert_user, enforce

@patch('enforcer.log_block')
@patch('shutil.move')
@patch('pathlib.Path.exists')
@patch('pathlib.Path.mkdir')
def test_quarantine_file(mock_mkdir, mock_exists, mock_move, mock_log_block):
    mock_exists.side_effect = [True, False]
    result = quarantine_file("/fake/path/malware.exe", "DummySig", "fakehash")
    assert result is True
    mock_move.assert_called_once()
    mock_log_block.assert_called_once_with("/fake/path/malware.exe", mock_move.call_args[0][1], "DummySig", "fakehash")

@patch('plyer.notification.notify')
def test_alert_user(mock_notify):
    alert_user()
    mock_notify.assert_called_once_with(
        title="WardenX Alert",
        message="Malicious file quarantined",
        app_name="WardenX",
        timeout=10
    )

@patch('enforcer.quarantine_file', return_value=True)
@patch('enforcer.alert_user')
def test_enforce(mock_alert, mock_quarantine):
    enforce("/fake/path/malware.exe", "DummySig", "fakehash")
    mock_quarantine.assert_called_once_with("/fake/path/malware.exe", "DummySig", "fakehash")
    mock_alert.assert_called_once()
