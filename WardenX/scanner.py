import os
import sys
import logging
from pathlib import Path
from analyzer import analyze_file
from database import log_scan

logging.basicConfig(level=logging.INFO, format="%(asctime)s - [%(levelname)s] - %(message)s")

def scan_directory(target_path, progress_callback=None):
    """
    Recursively scans all files in a directory using analyzer.analyze_file.
    
    :param target_path: Path to the directory to scan.
    :param progress_callback: Optional callable func(current_file, scanned_count, total_files, threats_found).
    :return: dict containing scan statistics: {'scanned': int, 'malicious': int, 'threats': list, 'errors': int}
    """
    target = Path(target_path)
    if not target.exists() or not target.is_dir():
        logging.error(f"Invalid target directory: {target_path}")
        return {"scanned": 0, "malicious": 0, "threats": [], "errors": 1}

    logging.info(f"Starting scan of directory: {target}")

    # Gather list of all files first for progress calculation
    all_files = []
    for root, _, files in os.walk(target):
        for file in files:
            all_files.append(os.path.join(root, file))

    total_files = len(all_files)
    logging.info(f"Found {total_files} file(s) to scan.")

    results = {
        "scanned": 0,
        "malicious": 0,
        "threats": [],
        "errors": 0
    }

    for idx, filepath in enumerate(all_files, start=1):
        try:
            logging.info(f"[{idx}/{total_files}] Scanning: {filepath}")
            is_malicious, signature = analyze_file(filepath)
            results["scanned"] += 1

            if is_malicious:
                results["malicious"] += 1
                threat_info = {"path": filepath, "signature": signature or "Unknown Threat"}
                results["threats"].append(threat_info)
                logging.warning(f"[MALICIOUS] {filepath} - Signature: {signature}")

            if progress_callback:
                progress_callback(filepath, idx, total_files, results["malicious"])

        except Exception as e:
            results["errors"] += 1
            logging.error(f"Error scanning {filepath}: {e}")
            if progress_callback:
                progress_callback(filepath, idx, total_files, results["malicious"])

    logging.info(
        f"Scan complete. Scanned: {results['scanned']}, Malicious: {results['malicious']}, Errors: {results['errors']}"
    )
    return results

if __name__ == "__main__":
    scan_dir = sys.argv[1] if len(sys.argv) > 1 else "."
    print(f"Scanning target: {scan_dir}")
    stats = scan_directory(scan_dir)
    print("\n--- Scan Results ---")
    print(f"Total Scanned: {stats['scanned']}")
    print(f"Malicious Found: {stats['malicious']}")
    print(f"Errors: {stats['errors']}")
    if stats["threats"]:
        print("Threat Details:")
        for threat in stats["threats"]:
            print(f"  - {threat['path']}: {threat['signature']}")
