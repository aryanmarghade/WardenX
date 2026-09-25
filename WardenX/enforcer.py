import os
import shutil
import logging
from pathlib import Path
from database import log_block, log_scan

def trigger_lockdown(canary_path):
    log_scan(canary_path, "N/A", "Behavioral (Canary)", "Ransomware Detected")
    if os.environ.get("WARDENX_HEADLESS") == "1":
        logging.info("Skipping lockdown notification in headless test mode.")
        return
    try:
        from plyer import notification
        notification.notify(
            title="CRITICAL: Ransomware Detected!",
            message=f"Active encryption behavior intercepted on {Path(canary_path).name}",
            app_name="WardenX",
            timeout=10
        )
    except ImportError:
        logging.warning("plyer not installed.")
        if os.name == 'posix':
            try:
                os.system('notify-send -u critical "CRITICAL: Ransomware Detected!" "Active encryption behavior intercepted"')
            except Exception:
                pass
    except Exception as e:
        logging.error(f"Failed to send lockdown notification: {e}")

def get_quarantine_dir():
    home_dir = Path.home()
    quarantine_dir = home_dir / ".wardenx_quarantine"
    quarantine_dir.mkdir(parents=True, exist_ok=True)
    return quarantine_dir

def quarantine_file(file_path, threat_signature, file_hash):
    try:
        file_path_obj = Path(file_path)
        if not file_path_obj.exists():
            return False
            
        quarantine_dir = get_quarantine_dir()
        target_path = quarantine_dir / file_path_obj.name
        
        counter = 1
        while target_path.exists():
            target_path = quarantine_dir / f"{file_path_obj.stem}_{counter}{file_path_obj.suffix}"
            counter += 1
            
        shutil.move(str(file_path_obj), str(target_path))
        log_block(file_path, str(target_path), threat_signature, file_hash)
        logging.info(f"Quarantined {file_path} to {target_path}")
        return True
    except Exception as e:
        logging.error(f"Failed to quarantine {file_path}: {e}")
        return False

def alert(message="Malicious file quarantined", title="WardenX Alert"):
    if os.environ.get("WARDENX_HEADLESS") == "1":
        logging.info(f"Skipping notification in headless test mode: {message}")
        return
    try:
        from plyer import notification
        notification.notify(
            title=title,
            message=message,
            app_name="WardenX",
            timeout=10
        )
    except ImportError:
        logging.warning("plyer not installed.")
        if os.name == 'posix':
            try:
                os.system(f'notify-send "{title}" "{message}"')
            except Exception:
                pass
    except Exception as e:
        logging.error(f"Failed to send desktop notification: {e}")

def alert_user():
    alert("Malicious file quarantined", "WardenX Alert")

def enforce(file_path, threat_signature, file_hash):
    if quarantine_file(file_path, threat_signature, file_hash):
        alert_user()
