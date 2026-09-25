import time
import logging
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from analyzer import analyze_file, calculate_sha256
from enforcer import enforce, trigger_lockdown
from canary_manager import get_deployed_canaries
import config

TEMP_DOWNLOAD_EXTENSIONS = ('.crdownload', '.part', '.download', '.tmp', '.opdownload')

class DownloadEventHandler(FileSystemEventHandler):
    def __init__(self):
        super().__init__()
        self.canaries = get_deployed_canaries()

    def on_created(self, event):
        if not event.is_directory:
            file_path = event.src_path
            # Ignore intermediate browser download chunks
            if file_path.lower().endswith(TEMP_DOWNLOAD_EXTENSIONS):
                logging.info(f"Browser download in progress: {file_path}")
                return
            self._handle_file(file_path, is_browser_download=False)

    def on_moved(self, event):
        if not event.is_directory:
            src_lower = event.src_path.lower()
            dest_lower = event.dest_path.lower()

            # Check if this move represents a finished browser download (renamed from .crdownload/.part)
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
            logging.info(f"[BROWSER SHIELD] Intercepted new download: {file_path}")
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

    home_dir = Path.home()
    directories_to_watch = [
        home_dir / "Downloads",
        home_dir / "Desktop"
    ]

    event_handler = DownloadEventHandler()
    observer = Observer()

    active_watches = 0
    for directory in directories_to_watch:
        if directory.exists() and directory.is_dir():
            observer.schedule(event_handler, str(directory), recursive=False)
            logging.info(f"Watching directory: {directory}")
            active_watches += 1
        else:
            logging.warning(f"Directory not found: {directory}")

    if active_watches == 0:
        logging.warning("No directories found to watch. Watching home directory.")
        observer.schedule(event_handler, str(home_dir), recursive=False)

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
