import time
import logging
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from analyzer import analyze_file, calculate_sha256
from enforcer import enforce

class DownloadEventHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            self._handle_file(event.src_path)
            
    def on_moved(self, event):
        if not event.is_directory:
            self._handle_file(event.dest_path)

    def _handle_file(self, file_path):
        if not file_path.endswith(('.crdownload', '.part', '.tmp')):
            logging.info(f"New file detected: {file_path}")
            time.sleep(1)
            
            is_malicious, signature = analyze_file(file_path)
            if is_malicious:
                file_hash = calculate_sha256(file_path)
                enforce(file_path, signature, file_hash)

def start_watching():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    
    home_dir = Path.home()
    directories_to_watch = [
        home_dir / "Downloads",
        home_dir / "Desktop"
    ]
    
    event_handler = DownloadEventHandler()
    observer = Observer()
    
    for directory in directories_to_watch:
        if directory.exists() and directory.is_dir():
            observer.schedule(event_handler, str(directory), recursive=False)
            logging.info(f"Watching directory: {directory}")
        else:
            logging.warning(f"Directory not found: {directory}")
            
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
