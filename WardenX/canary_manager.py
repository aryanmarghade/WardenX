import os
import json
import logging
from pathlib import Path
import ctypes
import config

CANARY_NAMES = [
    ".~password_backup.txt",
    ".~tax_return_2025.pdf",
    ".~crypto_wallet.dat"
]

def get_state_file():
    return Path.home() / ".wardenx_canaries.json"

def _hide_file_windows(file_path):
    if os.name == 'nt':
        FILE_ATTRIBUTE_HIDDEN = 0x02
        ctypes.windll.kernel32.SetFileAttributesW(str(file_path), FILE_ATTRIBUTE_HIDDEN)

def deploy_canaries():
    if not config.get_state('CANARY_ACTIVE'):
        return
        
    home_dir = Path.home()
    target_dirs = [
        home_dir / "Documents",
        home_dir / "Desktop"
    ]
    
    deployed_paths = []
    
    for d in target_dirs:
        if d.exists() and d.is_dir():
            for name in CANARY_NAMES:
                canary_path = d / name
                try:
                    # Create the canary file
                    with open(canary_path, 'w') as f:
                        f.write("DO NOT MODIFY. WardenX Canary file.\n" * 10)
                    
                    _hide_file_windows(canary_path)
                    deployed_paths.append(str(canary_path))
                except Exception as e:
                    logging.warning(f"Failed to deploy canary at {canary_path}: {e}")
                    
    state_file = get_state_file()
    try:
        with open(state_file, 'w') as f:
            json.dump(deployed_paths, f)
        logging.info(f"Deployed {len(deployed_paths)} canary files.")
    except Exception as e:
        logging.error(f"Failed to save canary state: {e}")

def cleanup_canaries():
    state_file = get_state_file()
    if not state_file.exists():
        return
        
    try:
        with open(state_file, 'r') as f:
            deployed_paths = json.load(f)
            
        for path_str in deployed_paths:
            p = Path(path_str)
            if p.exists():
                try:
                    p.unlink()
                except Exception as e:
                    logging.warning(f"Failed to delete canary {path_str}: {e}")
                    
        state_file.unlink(missing_ok=True)
        logging.info("Canary files cleaned up.")
    except Exception as e:
        logging.error(f"Error cleaning up canaries: {e}")

def get_deployed_canaries():
    state_file = get_state_file()
    if not state_file.exists():
        return []
        
    try:
        with open(state_file, 'r') as f:
            return json.load(f)
    except Exception:
        return []
