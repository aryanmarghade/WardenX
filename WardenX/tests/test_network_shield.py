import pytest
from unittest.mock import patch, MagicMock

scapy = pytest.importorskip("scapy")
from scapy.all import IP, TCP
import network_shield

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
