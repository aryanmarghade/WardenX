import time
import threading
import logging
from scapy.all import sniff, IP, TCP
import psutil
from database import log_network_event
from enforcer import alert
import config

logging.basicConfig(level=logging.INFO, format='%(asctime)s - [%(levelname)s] - %(message)s')

# DDoS Prevention (Rate Limiting) settings
SYN_WINDOW_SECONDS = 5
MAX_CONNECTIONS = 50
syn_tracker = {}
syn_tracker_lock = threading.Lock()

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
        if IP in packet and TCP in packet:
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
                    # Insecure HTTP allowed with alert/log if HTTPS enforcement is disabled
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
        pass
