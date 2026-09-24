import pytest
from unittest.mock import patch, mock_open
from service_manager import install_service, _install_windows_task, _install_linux_systemd

@patch('service_manager._install_windows_task')
@patch('service_manager._install_linux_systemd')
def test_install_service_routing(mock_linux, mock_windows, mocker):
    mocker.patch('os.name', 'nt')
    install_service()
    mock_windows.assert_called_once()
    mock_linux.assert_not_called()
    
    mock_windows.reset_mock()
    mock_linux.reset_mock()
    
    mocker.patch('os.name', 'posix')
    install_service()
    mock_linux.assert_called_once()
    mock_windows.assert_not_called()

@patch('subprocess.run')
def test_install_windows_task_direct(mock_run):
    mock_run.return_value.returncode = 0
    _install_windows_task()
    mock_run.assert_called_once()
    args = mock_run.call_args[0][0]
    assert args[0] == "powershell"

@patch('subprocess.run')
@patch('pathlib.Path.mkdir')
def test_install_linux_systemd_direct(mock_mkdir, mock_run, mocker):
    mocker.patch('builtins.open', mock_open())
    _install_linux_systemd()
    assert mock_run.call_count == 2
    assert "systemctl" in mock_run.call_args_list[0][0][0]
    assert "systemctl" in mock_run.call_args_list[1][0][0]
