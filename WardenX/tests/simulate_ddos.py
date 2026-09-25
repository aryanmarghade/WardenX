import time
import socket
import threading

def simulate_ddos(target_ip="127.0.0.1", target_port=80, num_connections=60):
    print(f"[*] Simulating rapid SYN-like connection flood to {target_ip}:{target_port}...")
    
    def connect():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect((target_ip, target_port))
            s.close()
        except Exception:
            pass

    threads = []
    for i in range(num_connections):
        t = threading.Thread(target=connect)
        threads.append(t)
        t.start()
        
    for t in threads:
        t.join()
        
    print(f"[*] Sent {num_connections} connection requests.")
    print("[*] If WardenX network shield is running, this should have triggered a DDoS mitigation log.")

if __name__ == "__main__":
    simulate_ddos()
