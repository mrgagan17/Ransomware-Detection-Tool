import os
import time
import hashlib
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Define the folder you want to monitor
MONITOR_FOLDER = "./monitor_folder"
# Define a file to log suspicious activities
LOG_FILE = "ransomware_detection.log"

# Function to generate hash of a file
def hash_file(filepath):
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
    except FileNotFoundError:
        print(f"[ERROR] File not found: {filepath}")
        return None
    return sha256_hash.hexdigest()

# Event handler for monitoring changes
class RansomwareDetector(FileSystemEventHandler):
    def __init__(self):
        # Dictionary to store initial file hashes
        self.file_hashes = {}

        # Record initial hashes of all files in the folder
        for root, dirs, files in os.walk(MONITOR_FOLDER):
            for filename in files:
                filepath = os.path.join(root, filename)
                self.file_hashes[filepath] = hash_file(filepath)

    def on_modified(self, event):
        if not event.is_directory:
            filepath = event.src_path
            if os.path.exists(filepath):
                new_hash = hash_file(filepath)
                old_hash = self.file_hashes.get(filepath)

                if old_hash and new_hash and new_hash != old_hash:
                    self.file_hashes[filepath] = new_hash
                    with open(LOG_FILE, "a") as log:
                        log.write(f"[ALERT] File modified: {filepath} at {time.ctime()}\n")
                    print(f"[ALERT] File modified: {filepath}")

    def on_created(self, event):
        if not event.is_directory:
            filepath = event.src_path
            if os.path.exists(filepath):
                self.file_hashes[filepath] = hash_file(filepath)
                with open(LOG_FILE, "a") as log:
                    log.write(f"[INFO] New file created: {filepath} at {time.ctime()}\n")
                print(f"[INFO] New file created: {filepath}")

    def on_deleted(self, event):
        if not event.is_directory:
            filepath = event.src_path
            if filepath in self.file_hashes:
                del self.file_hashes[filepath]
                with open(LOG_FILE, "a") as log:
                    log.write(f"[ALERT] File deleted: {filepath} at {time.ctime()}\n")
                print(f"[ALERT] File deleted: {filepath}")

# Main function to start monitoring
def monitor_folder():
    event_handler = RansomwareDetector()
    observer = Observer()
    observer.schedule(event_handler, MONITOR_FOLDER, recursive=True)
    observer.start()
    print(f"Monitoring folder: {MONITOR_FOLDER}")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    if not os.path.exists(MONITOR_FOLDER):
        os.makedirs(MONITOR_FOLDER)
    monitor_folder()
