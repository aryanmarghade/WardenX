import os
import sys
import subprocess
import logging
from pathlib import Path

def install_service():
    """Installs WardenX as a persistent background service."""
    if os.name == 'nt':
        _install_windows_task()
    else:
        _install_linux_systemd()

def _install_windows_task():
    try:
        script_path = Path(__file__).parent / "tray_app.py"
        python_exe = sys.executable
        task_name = "WardenX_EDR"
        
        # Use powershell to create a scheduled task on logon
        ps_command = (
            f"$Action = New-ScheduledTaskAction -Execute '{python_exe}' -Argument '{script_path}'; "
            f"$Trigger = New-ScheduledTaskTrigger -AtLogOn; "
            f"Register-ScheduledTask -Action $Action -Trigger $Trigger -TaskName '{task_name}' -Description 'WardenX EDR Daemon' -Force"
        )
        
        result = subprocess.run(["powershell", "-Command", ps_command], capture_output=True, text=True)
        if result.returncode == 0:
            print("Successfully registered WardenX Windows Scheduled Task.")
        else:
            print(f"Failed to register task: {result.stderr}")
    except Exception as e:
        print(f"Error installing Windows service: {e}")

def _install_linux_systemd():
    try:
        service_content = f"""[Unit]
Description=WardenX EDR Daemon
After=network.target

[Service]
ExecStart={sys.executable} {Path(__file__).parent / 'tray_app.py'}
Restart=always
User={os.getenv('USER', 'root')}

[Install]
WantedBy=default.target
"""
        service_path = Path.home() / ".config" / "systemd" / "user"
        service_path.mkdir(parents=True, exist_ok=True)
        
        file_path = service_path / "wardenx.service"
        with open(file_path, "w") as f:
            f.write(service_content)
            
        subprocess.run(["systemctl", "--user", "daemon-reload"])
        subprocess.run(["systemctl", "--user", "enable", "wardenx.service"])
        print(f"Successfully installed and enabled systemd service at {file_path}")
    except Exception as e:
        print(f"Error installing Linux service: {e}")
