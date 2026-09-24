import pytest
from unittest.mock import patch
from watcher import DownloadEventHandler
from watchdog.events import FileCreatedEvent, FileMovedEvent

@patch('watcher.analyze_file')
@patch('watcher.enforce')
@patch('time.sleep')
def test_watcher_ignores_crdownload(mock_sleep, mock_enforce, mock_analyze):
    handler = DownloadEventHandler()
    event = FileCreatedEvent("/fake/path/download.crdownload")
    handler.on_created(event)
    mock_analyze.assert_not_called()
    mock_enforce.assert_not_called()

@patch('watcher.calculate_sha256', return_value="fakehash")
@patch('watcher.analyze_file', return_value=(True, "DummySig"))
@patch('watcher.enforce')
@patch('time.sleep')
def test_watcher_handles_moved_crdownload(mock_sleep, mock_enforce, mock_analyze, mock_hash):
    handler = DownloadEventHandler()
    event = FileMovedEvent("/fake/path/download.crdownload", "/fake/path/malware.exe")
    handler.on_moved(event)
    
    mock_analyze.assert_called_once_with("/fake/path/malware.exe")
    mock_hash.assert_called_once_with("/fake/path/malware.exe")
    mock_enforce.assert_called_once_with("/fake/path/malware.exe", "DummySig", "fakehash")
