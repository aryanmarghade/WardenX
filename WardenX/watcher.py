import os
import time
import logging
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from analyzer import analyze_file, calculate_sha256
from enforcer import enforce, trigger_lockdown
from canary_manager import get_deployed_canaries
import config

# Temporary download extensions for Chrome (.crdownload), Firefox (.part), and other browsers
TEMP_DOWNLOAD_EXTENSIONS = ('.crdownload', '.part', '.download', '.tmp', '.opdownload')

def get_monitored_directories():
    """
    Resolves monitored directories across Linux and Windows environments cleanly.
    Ensures Downloads and Desktop paths exist and handles XDG fallbacks on Linux.
    """
    home_dir = Path.home()
    directories = []

    # 1. Downloads Directory
    downloads_dir = home_dir / "Downloads"
    xdg_downloads = os.environ.get("XDG_DOWNLOAD_DIR")
    if xdg_downloads and Path(xdg_downloads).exists():
        downloads_dir = Path(xdg_downloads)

    if downloads_dir.exists() and downloads_dir.is_dir():
        directories.append(downloads_dir)
    else:
        # Create or fallback to home
        try:
            downloads_dir.mkdir(parents=True, exist_ok=True)
            directories.append(downloads_dir)
        except Exception:
            pass

    # 2. Desktop Directory
    desktop_dir = home_dir / "Desktop"
    xdg_desktop = os.environ.get("XDG_DESKTOP_DIR")
    if xdg_desktop and Path(xdg_desktop).exists():
        desktop_dir = Path(xdg_desktop)

    if desktop_dir.exists() and desktop_dir.is_dir():
        directories.append(desktop_dir)

    # Fallback to home directory if nothing else found
    if not directories:
        directories.append(home_dir)

    return directories

class DownloadEventHandler(FileSystemEventHandler):
    def __init__(self):
        super().__init__()
        self.canaries = get_deployed_canaries()

    def on_created(self, event):
        if not event.is_directory:
            file_path = event.src_path
            # Ignore intermediate browser download chunks (.crdownload / .part)
            if file_path.lower().endswith(TEMP_DOWNLOAD_EXTENSIONS):
                logging.info(f"Browser download in progress: {file_path}")
                return
            self._handle_file(file_path, is_browser_download=False)

    def on_moved(self, event):
        if not event.is_directory:
            src_lower = event.src_path.lower()
            dest_lower = event.dest_path.lower()

            # Detect when a browser download finishes (renamed from .crdownload or .part to final extension)
            is_download_completion = (
                src_lower.endswith(TEMP_DOWNLOAD_EXTENSIONS) and
                not dest_lower.endswith(TEMP_DOWNLOAD_EXTENSIONS)
            )

            if is_download_completion:
                logging.info(f"Browser download finalized: {event.src_path} -> {event.dest_path}")
                self._handle_file(event.dest_path, is_browser_download=True)
            else:
                if not dest_lower.endswith(TEMP_DOWNLOAD_EXTENSIONS):
                    self._handle_file(event.dest_path, is_browser_download=False)

            self._check_canary(event.src_path)
            self._check_canary(event.dest_path)

    def on_modified(self, event):
        if not event.is_directory:
            self._check_canary(event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self._check_canary(event.src_path)

    def _check_canary(self, file_path):
        if config.get_state('CANARY_ACTIVE') and str(Path(file_path)) in self.canaries:
            trigger_lockdown(file_path)

    def _handle_file(self, file_path, is_browser_download=False):
        # Determine whether to process based on active configuration
        if is_browser_download:
            if not config.get_state('BROWSER_PROTECTION_ACTIVE'):
                return
            logging.info(f"[BROWSER SHIELD] Intercepted completed download: {file_path}")
        else:
            if not config.get_state('FILE_WATCHER_ACTIVE'):
                return
            logging.info(f"[FILE WATCHER] New file detected: {file_path}")

        # Short pause to ensure file write buffer is fully flushed by OS/browser
        time.sleep(0.5)

        try:
            is_malicious, signature = analyze_file(file_path)
            if is_malicious:
                logging.warning(f"Malware intercepted! Target: {file_path} | Signature: {signature}")
                file_hash = calculate_sha256(file_path)
                enforce(file_path, signature, file_hash)
        except Exception as e:
            logging.error(f"Error analyzing file {file_path}: {e}")

def start_watching():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - [%(levelname)s] - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

    directories_to_watch = get_monitored_directories()
    event_handler = DownloadEventHandler()
    observer = Observer()

    for directory in directories_to_watch:
        try:
            observer.schedule(event_handler, str(directory), recursive=False)
            logging.info(f"Watching directory: {directory}")
        except Exception as e:
            logging.warning(f"Could not watch directory {directory}: {e}")

    observer.start()
    logging.info("WardenX watcher started.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        logging.info("WardenX watcher stopped.")

    observer.join()

if __name__ == "__main__":
    start_watching()
