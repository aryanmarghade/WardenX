import time
import threading
from scapy.all import sniff, IP, TCP
import psutil
from database import log_network_event
from enforcer import alert
import config

# DDoS Prevention (Rate Limiting) settings
# sliding window dictionary that tracks the number of SYN packets from a specific IP within a 5-second window
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
                        log_network_event(src_ip, dst_ip, dport, "TCP", "Blocked (DDoS Mitigation)")
                        # In a real environment, we might drop the packet or ban the IP using firewall rules.
                        return

            # 2. HTTPS Enforcement: Outbound traffic on Port 80
            # Assuming outbound means src_ip is local. We can just alert if dport is 80.
            if dport == 80:
                alert("Insecure HTTP connection detected")
                log_network_event(src_ip, dst_ip, 80, "TCP", "Alerted (Port 80)")
                return

            # 3. Activity Logging: Log standard outbound HTTPS (Port 443)
            if dport == 443:
                # Log only SYN to avoid logging every packet, or log all?
                # "Log standard outbound HTTPS (Port 443) connection IPs to the network_logs database as "Allowed"."
                # Better to log just the SYN to avoid flooding
                if flags == 'S':
                    log_network_event(src_ip, dst_ip, 443, "TCP", "Allowed")
                    
    except Exception:
        # Fails gracefully if it encounters malformed packets
        pass

def _start_sniffing_thread():
    # store=False prevents scapy from keeping packets in memory
    sniff(prn=process_packet, store=False)

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
