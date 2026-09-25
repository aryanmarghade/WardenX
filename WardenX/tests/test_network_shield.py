import pytest
from unittest.mock import patch, MagicMock
import subprocess
import network_shield

scapy = pytest.importorskip("scapy")
from scapy.all import IP, TCP

def test_network_shield_https_enforcement():
    packet = IP(src="192.168.1.10", dst="93.184.216.34") / TCP(sport=54321, dport=80, flags="S")
    
    with patch('config.get_state') as mock_state, \
         patch('network_shield.log_network_event') as mock_log, \
         patch('network_shield.alert') as mock_alert:
        
        mock_state.side_effect = lambda k: True
        network_shield.process_packet(packet)
        
        mock_alert.assert_called_once_with(
            "Insecure HTTP connection blocked (Strict HTTPS Enforced)",
            "WardenX Network Shield"
        )
        mock_log.assert_called_once_with(
            "192.168.1.10", "93.184.216.34", 80, "TCP", "Insecure HTTP connection blocked"
        )

def test_network_shield_http_allowed_when_force_https_off():
    packet = IP(src="192.168.1.10", dst="93.184.216.34") / TCP(sport=54321, dport=80, flags="S")
    
    with patch('config.get_state') as mock_state, \
         patch('network_shield.log_network_event') as mock_log, \
         patch('network_shield.alert') as mock_alert:
        
        mock_state.side_effect = lambda k: False if k == "FORCE_HTTPS_ACTIVE" else True
        network_shield.process_packet(packet)
        
        mock_alert.assert_not_called()
        mock_log.assert_called_once_with(
            "192.168.1.10", "93.184.216.34", 80, "TCP", "Alerted (Port 80)"
        )

def test_linux_iptables_enable_and_disable():
    with patch('network_shield.is_linux', return_value=True), \
         patch('subprocess.run') as mock_subproc:
        
        # Test 1: Check returns 1 (rule not found), Add returns 0 (success)
        mock_check = MagicMock(returncode=1)
        mock_add = MagicMock(returncode=0)
        mock_subproc.side_effect = [mock_check, mock_add]
        
        res = network_shield.apply_iptables_https_enforcement(True)
        assert res is True
        assert mock_subproc.call_count == 2
        
        # Test 2: Disable - Check returns 0 (rule exists), Delete returns 0 (success)
        mock_check2 = MagicMock(returncode=0)
        mock_del = MagicMock(returncode=0)
        mock_subproc.side_effect = [mock_check2, mock_del]
        
        res_del = network_shield.apply_iptables_https_enforcement(False)
        assert res_del is True

def test_linux_iptables_graceful_permission_failure():
    with patch('network_shield.is_linux', return_value=True), \
         patch('subprocess.run', side_effect=PermissionError("sudo password required")):
        
        # Should not crash, returns False
        res = network_shield.apply_iptables_https_enforcement(True)
        assert res is False
