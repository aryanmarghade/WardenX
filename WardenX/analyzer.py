import hashlib
import os
import requests
import logging
from pathlib import Path
from database import log_scan

def calculate_sha256(file_path):
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        logging.error(f"Error calculating hash for {file_path}: {e}")
        return None

def check_virustotal(file_hash):
    vt_api_key = os.environ.get("VT_API_KEY")
    if not vt_api_key:
        logging.warning("VT_API_KEY environment variable not found. Skipping VirusTotal check.")
        return False

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "accept": "application/json",
        "x-apikey": vt_api_key
    }
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            if malicious > 0:
                return True
        elif response.status_code == 404:
            return False
        else:
            logging.error(f"VirusTotal API error: {response.status_code}")
    except Exception as e:
        logging.error(f"Error communicating with VirusTotal API: {e}")
        
    return False

def scan_with_yara(file_path):
    try:
        import yara # type: ignore
        rules_path = Path(__file__).parent / 'rules' / 'malware.yar'
        if not rules_path.exists():
            logging.warning(f"Yara rules file not found: {rules_path}")
            return False, None
            
        rules = yara.compile(filepath=str(rules_path))
        matches = rules.match(str(file_path))
        if matches:
            return True, str(matches[0])
    except ImportError:
        logging.warning("yara-python not installed. Skipping local yara scan.")
    except Exception as e:
        logging.error(f"Error running Yara scan: {e}")
    return False, None

def analyze_file(file_path):
    logging.info(f"Analyzing file: {file_path}")
    
    file_hash = calculate_sha256(file_path)
    if not file_hash:
        return False, None
        
    logging.info(f"SHA-256: {file_hash}")
    
    is_yara_malicious, signature = scan_with_yara(file_path)
    if is_yara_malicious:
        logging.warning(f"Malware detected by Yara: {file_path}")
        log_scan(file_path, file_hash, "Yara", "Malicious")
        return True, signature
        
    from heuristics import calculate_entropy
    entropy = calculate_entropy(file_path)
    if entropy > 7.2:
        logging.warning(f"High entropy ({entropy:.2f}) detected by Heuristics: {file_path}")
        log_scan(file_path, file_hash, "Heuristics", "Malicious")
        return True, f"High Entropy ({entropy:.2f})"
        
    if check_virustotal(file_hash):
        logging.warning(f"Malware detected by VirusTotal: {file_path}")
        log_scan(file_path, file_hash, "VirusTotal", "Malicious")
        return True, "VirusTotal Detection"
        
    log_scan(file_path, file_hash, "All", "Benign")
    return False, None
