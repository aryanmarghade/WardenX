import json
import os
import threading
from pathlib import Path

CONFIG_FILE = Path.home() / ".wardenx_config.json"
_lock = threading.Lock()

DEFAULT_CONFIG = {
    "FILE_WATCHER_ACTIVE": True,
    "NETWORK_SHIELD_ACTIVE": True,
    "CANARY_ACTIVE": True
}

def _load_config():
    if not CONFIG_FILE.exists():
        return DEFAULT_CONFIG.copy()
    try:
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    except Exception:
        return DEFAULT_CONFIG.copy()

def _save_config(config):
    with _lock:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f)

def get_state(module_name):
    config = _load_config()
    return config.get(module_name, True)

def set_state(module_name, state):
    config = _load_config()
    config[module_name] = bool(state)
    _save_config(config)

def set_all_states(state):
    config = _load_config()
    for key in DEFAULT_CONFIG.keys():
        config[key] = bool(state)
    _save_config(config)

# Initialize
if not CONFIG_FILE.exists():
    _save_config(DEFAULT_CONFIG)
