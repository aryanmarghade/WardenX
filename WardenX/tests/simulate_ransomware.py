import os
from pathlib import Path

def simulate_encryption():
    target_dirs = [Path.home() / "Documents", Path.home() / "Desktop"]
    encrypted_count = 0
    
    for target_dir in target_dirs:
        print(f"[*] Scanning {target_dir} for canary files to 'encrypt'...")
        
        if not target_dir.exists() or not target_dir.is_dir():
            print(f"[-] Directory {target_dir} does not exist.")
            continue

        for root, _, files in os.walk(target_dir):
            for file in files:
                if file.startswith('.~'):
                    file_path = Path(root) / file
                    try:
                        with open(file_path, 'a') as f:
                            f.write("\nENCRYPTED_BY_SIMULATOR")
                        print(f"[+] 'Encrypted': {file_path}")
                        encrypted_count += 1
                    except Exception as e:
                        print(f"[-] Failed to access {file_path}: {e}")
                    
    if encrypted_count > 0:
        print(f"[*] Successfully 'encrypted' {encrypted_count} canary files.")
    else:
        print("[-] No canary files found. Is WardenX running? Try running 'python cli.py on'")

if __name__ == "__main__":
    simulate_encryption()
