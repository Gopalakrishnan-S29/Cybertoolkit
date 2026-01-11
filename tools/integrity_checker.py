import os
import hashlib
import json
from datetime import datetime

# -------------------------------------------------
# Paths
# -------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BASELINE_FILE = os.path.join(BASE_DIR, "integrity_baseline.json")
CUSTOM_FILES_FILE = os.path.join(BASE_DIR, "custom_files.json")

# -------------------------------------------------
# OS-aware system files
# -------------------------------------------------
if os.name == "nt":  # Windows
    MONITORED_FILES = [
        r"C:\Windows\System32\drivers\etc\hosts",
        r"C:\Windows\System32\GroupPolicy\Machine\Registry.pol",
        r"C:\Windows\System32\LogFiles\Firewall\pfirewall.log"
    ]
else:  # Linux / Unix
    MONITORED_FILES = [
        "/etc/hosts",
        "/etc/passwd",
        "/etc/group"
    ]

# -------------------------------------------------
# Hash calculation
# -------------------------------------------------
def calculate_hash(file_path):
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for block in iter(lambda: f.read(4096), b""):
                sha256.update(block)
        return sha256.hexdigest()
    except Exception:
        return None

# -------------------------------------------------
# Custom files handling
# -------------------------------------------------
def load_custom_files():
    if not os.path.exists(CUSTOM_FILES_FILE):
        return []

    with open(CUSTOM_FILES_FILE, "r") as f:
        return json.load(f)

def save_custom_file(file_path):
    files = load_custom_files()

    if os.path.isfile(file_path) and file_path not in files:
        files.append(file_path)

    with open(CUSTOM_FILES_FILE, "w") as f:
        json.dump(files, f, indent=4)

# -------------------------------------------------
# Baseline creation
# -------------------------------------------------
def create_baseline():
    baseline = {}
    files_to_monitor = MONITORED_FILES + load_custom_files()

    for file in files_to_monitor:
        file_hash = calculate_hash(file)
        if file_hash:
            baseline[file] = {
                "hash": file_hash,
                "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }

    with open(BASELINE_FILE, "w") as f:
        json.dump(baseline, f, indent=4)

    return baseline

# -------------------------------------------------
# Load baseline
# -------------------------------------------------
def load_baseline():
    if not os.path.exists(BASELINE_FILE):
        return None

    with open(BASELINE_FILE, "r") as f:
        return json.load(f)

# -------------------------------------------------
# Integrity check
# -------------------------------------------------
def check_integrity():
    baseline = load_baseline()

    # IMPORTANT: None ≠ empty dict
    if baseline is None:
        return None, "Baseline not created"

    results = []

    for file, data in baseline.items():
        current_hash = calculate_hash(file)

        if not current_hash:
            status = "File not accessible"
            integrity = "Unknown"
        elif current_hash == data["hash"]:
            status = "Unchanged"
            integrity = "OK"
        else:
            status = "Modified"
            integrity = "Alert"

        results.append({
            "file": file,
            "status": status,
            "integrity": integrity
        })

    return results, None

def remove_custom_file(file_path):
    files = load_custom_files()

    if file_path in files:
        files.remove(file_path)

        with open(CUSTOM_FILES_FILE, "w") as f:
            json.dump(files, f, indent=4)

