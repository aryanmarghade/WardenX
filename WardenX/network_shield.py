import os
import time
import threading
import logging
import platform
import subprocess
try:
    from scapy.all import sniff, IP, TCP
except ImportError:
    sniff = None
    IP = None
    TCP = None
from database import log_network_event
from enforcer import alert
import config

logging.basicConfig(level=logging.INFO, format='%(asctime)s - [%(levelname)s] - %(message)s')

# DDoS Prevention (Rate Limiting) settings
SYN_WINDOW_SECONDS = 5
MAX_CONNECTIONS = 50
syn_tracker = {}
syn_tracker_lock = threading.Lock()

def is_linux():
    return platform.system() == "Linux"

def is_windows():
    return platform.system() == "Windows"

def _run_iptables_command(cmd_args):
    """
    Executes an iptables command. Attempts sudo if not running as root.
    Catches permissions, timeouts, and missing binary errors gracefully.
    """
    try:
        is_root = (os.geteuid() == 0) if hasattr(os, 'geteuid') else False
        if is_root:
            cmd = ["iptables"] + cmd_args
        else:
            cmd = ["sudo", "-n", "iptables"] + cmd_args

        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5
        )
        return result.returncode == 0
    except (subprocess.SubprocessError, FileNotFoundError, PermissionError) as e:
        logging.debug(f"iptables command execution notice ({' '.join(cmd_args)}): {e}")
        return False
    except Exception as e:
        logging.debug(f"Unexpected iptables execution error: {e}")
        return False

def apply_iptables_https_enforcement(enable: bool):
    """
    On Linux, injects or removes an iptables firewall rule to DROP outbound Port 80 (HTTP).
    Rule: iptables -A OUTPUT -p tcp --dport 80 -j DROP
    """
    if not is_linux():
        return False

    rule_check = ["-C", "OUTPUT", "-p", "tcp", "--dport", "80", "-j", "DROP"]
    rule_add = ["-A", "OUTPUT", "-p", "tcp", "--dport", "80", "-j", "DROP"]
    rule_del = ["-D", "OUTPUT", "-p", "tcp", "--dport", "80", "-j", "DROP"]

    rule_exists = _run_iptables_command(rule_check)

    if enable:
        if not rule_exists:
            success = _run_iptables_command(rule_add)
            if success:
                logging.info("[IPTABLES] Active: Injected DROP rule for outbound Port 80 (Strict HTTPS).")
            else:
                logging.warning("[IPTABLES] Could not insert iptables rule. Ensure root or passwordless sudo privileges.")
            return success
        return True
    else:
        if rule_exists:
            success = _run_iptables_command(rule_del)
            if success:
                logging.info("[IPTABLES] Inactive: Removed Port 80 DROP rule.")
            else:
                logging.warning("[IPTABLES] Could not delete iptables rule.")
            return success
        return True

def _run_windows_firewall_command(cmd_args):
    """Executes a Windows netsh advfirewall command."""
    try:
        cmd = ["netsh", "advfirewall", "firewall"] + cmd_args
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5
        )
        return result.returncode == 0
    except Exception as e:
        logging.debug(f"Windows firewall command error: {e}")
        return False

def apply_windows_firewall_https_enforcement(enable: bool):
    """
    On Windows, injects or removes a Windows Firewall rule to BLOCK outbound Port 80 (HTTP).
    Rule: netsh advfirewall firewall add rule name="WardenX_Block_HTTP" dir=out action=block protocol=TCP remoteport=80
    """
    if not is_windows():
        return False

    rule_name = "WardenX_Block_HTTP"
    show_cmd = ["show", "rule", f"name={rule_name}"]
    add_cmd = ["add", "rule", f"name={rule_name}", "dir=out", "action=block", "protocol=TCP", "remoteport=80"]
    del_cmd = ["delete", "rule", f"name={rule_name}"]

    rule_exists = _run_windows_firewall_command(show_cmd)

    if enable:
        if not rule_exists:
            success = _run_windows_firewall_command(add_cmd)
            if success:
                logging.info("[FIREWALL] Active: Injected Windows Firewall rule to BLOCK outbound Port 80.")
            else:
                logging.warning("[FIREWALL] Could not add Windows Firewall rule. Run WardenX as Administrator to enforce kernel-level HTTP dropping.")
            return success
        return True
    else:
        if rule_exists:
            success = _run_windows_firewall_command(del_cmd)
            if success:
                logging.info("[FIREWALL] Inactive: Removed Windows Firewall Port 80 rule.")
            return success
        return True

def sync_firewall_rules():
    """Synchronizes system firewall state with current configuration across Linux & Windows."""
    active = bool(config.get_state('FORCE_HTTPS_ACTIVE') and config.get_state('NETWORK_SHIELD_ACTIVE'))
    if is_linux():
        apply_iptables_https_enforcement(active)
    elif is_windows():
        apply_windows_firewall_https_enforcement(active)

def clean_tracker():
    """Remove IPs from tracker that are outside the 5-second window."""
    current_time = time.time()
    with syn_tracker_lock:
        for ip in list(syn_tracker.keys()):
            syn_tracker[ip] = [t for t in syn_tracker[ip] if current_time - t <= SYN_WINDOW_SECONDS]
            if not syn_tracker[ip]:
                del syn_tracker[ip]

def process_packet(packet):
    if not config.get_state('NETWORK_SHIELD_ACTIVE'):
        return

    try:
        if IP and TCP and IP in packet and TCP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            dport = packet[TCP].dport
            sport = packet[TCP].sport
            flags = packet[TCP].flags

            # 1. DDoS Prevention: track SYN packets from a specific IP
            if flags == 'S':  # SYN packet
                clean_tracker()
                with syn_tracker_lock:
                    if src_ip not in syn_tracker:
                        syn_tracker[src_ip] = []
                    syn_tracker[src_ip].append(time.time())

                    if len(syn_tracker[src_ip]) > MAX_CONNECTIONS:
                        logging.warning(f"DDoS rate limit exceeded for IP {src_ip}")
                        log_network_event(src_ip, dst_ip, dport, "TCP", "Blocked (DDoS Mitigation)")
                        return

            # 2. Strict HTTPS Enforcement: Intercept and Block Port 80 (HTTP) Traffic
            if dport == 80 or sport == 80:
                if config.get_state('FORCE_HTTPS_ACTIVE'):
                    logging.warning(f"[HTTPS ENFORCEMENT] Blocked insecure HTTP connection: {src_ip}:{sport} -> {dst_ip}:{dport}")
                    alert("Insecure HTTP connection blocked (Strict HTTPS Enforced)", "WardenX Network Shield")
                    log_network_event(src_ip, dst_ip, 80, "TCP", "Insecure HTTP connection blocked")
                    return
                else:
                    logging.info(f"[HTTP DETECTED] Unencrypted HTTP traffic: {src_ip}:{sport} -> {dst_ip}:{dport}")
                    log_network_event(src_ip, dst_ip, 80, "TCP", "Alerted (Port 80)")
                    return

            # 3. Secure HTTPS Traffic Logging (Port 443)
            if dport == 443:
                if flags == 'S':
                    log_network_event(src_ip, dst_ip, 443, "TCP", "Allowed (HTTPS)")

    except Exception as e:
        logging.debug(f"Packet parsing exception: {e}")

def _start_sniffing_thread():
    try:
        logging.info("Network Shield packet sniffing initialized.")
        sync_firewall_rules()
        if sniff:
            sniff(prn=process_packet, store=False)
    except Exception as e:
        logging.error(f"Error starting packet sniffer: {e}")

def start_sniffing():
    t = threading.Thread(target=_start_sniffing_thread, daemon=True)
    t.start()

if __name__ == '__main__':
    start_sniffing()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        if is_linux():
            apply_iptables_https_enforcement(False)
        elif is_windows():
            apply_windows_firewall_https_enforcement(False)
