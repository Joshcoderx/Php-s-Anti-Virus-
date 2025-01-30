import os
import hashlib
import time
import psutil
import shutil
import datetime
import random
import base64
import threading
import mmap
from plyer import notification

QUARANTINE_DIR = "quarantine"
LOG_FILE = "antivirus_results.txt"
KNOWN_MALWARE_HASHES = set()
DETECTION_RULES = ["eval(", "base64_decode(", "exec(", "import os", "subprocess.Popen"]
MAX_SCAN_DEPTH = 5
FILE_SIZE_LIMIT = 100 * 1024 * 1024
EXCLUSION_LIST = set()


def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def log_event(message, level="INFO"):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as log_file:
        log_file.write(f"[{timestamp}] [{level}] {message}\n")


def send_notification(message):
    notification.notify(
        title="Php's Anti-Virus Alert",
        message=message,
        timeout=10
    )


def generate_random_name(length=12):
    return ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=length))


def calculate_hash(file_path):
    try:
        with open(file_path, "rb") as f:
            file_hash = hashlib.sha256()
            while chunk := f.read(8192):
                file_hash.update(chunk)
        return file_hash.hexdigest()
    except Exception as e:
        log_event(f"Error calculating hash for {file_path}: {e}")
        return None


def load_known_malware_hashes():
    global KNOWN_MALWARE_HASHES
    known_hashes_file = "known_hashes.txt"
    if os.path.exists(known_hashes_file):
        with open(known_hashes_file, "r") as file:
            KNOWN_MALWARE_HASHES = set(file.read().splitlines())


def check_permissions(file_path):
    try:
        with open(file_path, 'r'):
            pass
    except PermissionError:
        log_event(f"Permission denied for {file_path}")
        return False
    return True


def move_to_quarantine(file_path):
    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    quarantine_path = os.path.join(QUARANTINE_DIR, f"{generate_random_name()}_{os.path.basename(file_path)}")
    shutil.move(file_path, quarantine_path)
    log_event(f"Quarantined: {file_path}")
    send_notification(f"Quarantined: {file_path}")


def heuristic_analysis(file_path):
    try:
        with open(file_path, "r", errors="ignore") as f:
            content = f.read()
            for rule in DETECTION_RULES:
                if rule in content:
                    return True
        return False
    except Exception as e:
        log_event(f"Error during heuristic analysis for {file_path}: {e}")
        return False


def scan_large_file(file_path):
    try:
        with open(file_path, 'rb') as f:
            mmapped_file = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
            for rule in DETECTION_RULES:
                if rule.encode() in mmapped_file:
                    return True
            return False
    except Exception as e:
        log_event(f"Error scanning large file {file_path}: {e}")
        return False


def scan_file(file_path):
    if not os.path.isfile(file_path) or file_path in EXCLUSION_LIST:
        return
    
    log_event(f"Scanning file: {file_path}")

    if os.path.getsize(file_path) > FILE_SIZE_LIMIT:
        log_event(f"Skipping large file: {file_path}")
        return

    file_hash = calculate_hash(file_path)
    if file_hash in KNOWN_MALWARE_HASHES:
        log_event(f"Known malware detected: {file_path}", "WARNING")
        move_to_quarantine(file_path)
        return

    if heuristic_analysis(file_path) or scan_large_file(file_path):
        log_event(f"Suspicious file detected: {file_path}", "WARNING")
        move_to_quarantine(file_path)


def scan_directory(directory, depth=0):
    if depth > MAX_SCAN_DEPTH:
        return

    try:
        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                scan_file(file_path)
    except Exception as e:
        log_event(f"Error scanning directory {directory}: {e}")


def monitor_processes():
    while True:
        for process in psutil.process_iter(attrs=['pid', 'name', 'exe']):
            try:
                if process.info['exe']:
                    scan_file(process.info['exe'])
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        time.sleep(10)


def start_scan(directory):
    load_known_malware_hashes()
    scan_directory(directory)
    log_event(f"Scan completed for {directory}")


if __name__ == "__main__":
    scan_path = input("Enter the directory to scan: ").strip()
    start_scan(scan_path)

    monitor_thread = threading.Thread(target=monitor_processes, daemon=True)
    monitor_thread.start()