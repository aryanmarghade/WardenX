import os
import sys
import time
import sqlite3
import subprocess
import threading
from http.server import SimpleHTTPRequestHandler, HTTPServer
from pathlib import Path

from selenium import webdriver # type: ignore
from selenium.webdriver.chrome.service import Service # type: ignore
from selenium.webdriver.chrome.options import Options # type: ignore
from webdriver_manager.chrome import ChromeDriverManager # type: ignore

def start_mock_server(port=8080):
    class MockHandler(SimpleHTTPRequestHandler):
        def do_GET(self):
            if self.path == '/eicar.com.txt':
                self.send_response(200)
                self.send_header("Content-type", "application/octet-stream")
                self.send_header("Content-Disposition", 'attachment; filename="eicar.com.txt"')
                self.end_headers()
                self.wfile.write(b"WARDENX-TEST-PAYLOAD-12345")
            else:
                self.send_response(404)
                self.end_headers()

    httpd = HTTPServer(('localhost', port), MockHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd

def run_test():
    project_dir = Path(__file__).parent.parent.absolute()
    cli_path = project_dir / "cli.py"
    db_path = Path.home() / ".wardenx_logs.db"
    download_dir = Path.home() / "Downloads"

    print("[*] Starting Local Mock Server on port 8080...")
    server = start_mock_server(8080)

    print("[*] Starting WardenX Daemon...")
    daemon_log_path = project_dir / "daemon_test.log"
    test_env = os.environ.copy()
    test_env["WARDENX_HEADLESS"] = "1"
    with open(daemon_log_path, "w") as log_f:
        subprocess.run([sys.executable, str(cli_path), "on"], stdout=log_f, stderr=log_f, env=test_env, check=True)
    time.sleep(3) 

    print("[*] Setting up Headless Chrome...")
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--no-sandbox")
    
    prefs = {
        "download.default_directory": str(download_dir),
        "download.prompt_for_download": False,
        "download.directory_upgrade": True,
        "safebrowsing.enabled": False
    }
    chrome_options.add_experimental_option("prefs", prefs)

    service = Service(ChromeDriverManager().install())
    driver = webdriver.Chrome(service=service, options=chrome_options)
    
    driver.execute_cdp_cmd('Page.setDownloadBehavior', {
        'behavior': 'allow',
        'downloadPath': str(download_dir)
    })

    try:
        print("[*] Navigating to Local Mock Server to trigger download...")
        driver.get("http://localhost:8080/eicar.com.txt")
        
        print("[*] Polling database for quarantine event...")
        found = False
        
        for _ in range(30):
            time.sleep(1)
            try:
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM block_history ORDER BY id DESC LIMIT 5')
                latest_blocks = cursor.fetchall()
                conn.close()
                
                for block in latest_blocks:
                    if "eicar" in block[2].lower():
                        print("[+] EICAR file successfully detected and quarantined!")
                        print(f"    Record: Original: {block[2]}, Quarantined: {block[3]}")
                        found = True
                        break
                
                if found:
                    break
            except Exception:
                pass 
                
        assert found, "[-] EICAR file was NOT detected and quarantined within 30 seconds."
        print("[+] E2E Integration Test PASSED successfully.")

    finally:
        print("[*] Closing browser and server...")
        driver.quit()
        server.shutdown()
        server.server_close()
        
        print("[*] Stopping WardenX Daemon...")
        subprocess.run([sys.executable, str(cli_path), "off"], check=True)
        
        print("--- CLI LOGS ---")
        if daemon_log_path.exists():
            with open(daemon_log_path, "r") as f:
                print(f.read())
        
        print("--- WATCHER LOGS ---")
        watcher_log = Path.home() / ".wardenx_daemon.log"
        if watcher_log.exists():
            with open(watcher_log, "r") as f:
                print(f.read())
        print("-------------------")

if __name__ == "__main__":
    run_test()
