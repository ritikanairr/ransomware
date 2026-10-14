"""
Ransomware Detection Tool

# Important!
- Libraries required: watchdog, sortedcontainers

# Authors:
    - Raz Cohen
    - Aliza Lazar

# Efficiency Analysis:
Definitions:
    - n = number of tracked files in the monitored directory
    - m = size (in bytes) of a single changed file

A. Memory Usage: O(n)
    - Per file:
        - SHA-256 hash: O(1)
        - MIME type string (text/binary): O(1)
        - Up to 4KB of content for fuzzy comparison: O(1)
        - Entropy map (one value per 1KB block): O(m / 1024) [Explanation: 1024 bytes = 1KB]
    - Memory scales linearly with number of files (n)

B. Runtime Complexity (per file event): O(m + log(n)) per event
    - SHA-256 hash (entire file): O(m)
    - Partial content read (first 4KB): O(1)
    - ASCII ratio, entropy, encoding detection (on 4KB): O(1)
    - Fuzzy similarity (first 4KB): O(1)
    - SortedDict access/update (hashes, types, contents): O(log(n))
    - Overall per-event runtime: O(m + log(n))

C. I/O Complexity: O(1) per event
    - File monitoring relies on real-time OS notifications (via Watchdog)
    - Partial read (~4KB) per changed file
    - No polling or folder-wide scanning
    - I/O is constant per file event, regardless of total folder size

# Sources:
We combined methods from a few research articles listed below:
    - Watchdog:
        https://medium.com/h7w/how-to-detect-malware-on-a-windows-system-using-python-a-step-by-step-guide-for-beginners-ebe98c7aa967
    - Fuzzy similarity:
        https://pure.port.ac.uk/ws/portalfiles/portal/20272871/1570559640.pdf
        https://www.cise.ufl.edu/~traynor/papers/scaife-icdcs16.pdf
    - Honeypot:
        https://www.researchgate.net/publication/309323786_Detecting_Ransomware_with_Honeypot_Techniques
    - Entropy & ASCII ratio & encoding detection:
        https://www.mdpi.com/1424-8220/24/5/1446
    - High-frequency file modifications (extended it to deletions as-well):
        https://www.techrxiv.org/doi/full/10.36227/techrxiv.173047864.44215173
"""

import os # for file system operations
import time # for time operations
import math # for mathematical operations
import hashlib # for hashing
import string # for string operations
import re # for regex operations
from collections import defaultdict, deque # for data structures
from sortedcontainers import SortedDict # for sorted dictionary
from watchdog.observers import Observer # for file system monitoring
from watchdog.events import FileSystemEventHandler # for event handling
import difflib # for fuzzy similarity
import base64 # for Base64 validation

MONITORED_DIR = r"C:\Users\ritik\Downloads\ransomware-detector-main\ransomware-detector-main\TestFiles" # Directory to monitor
MAX_EVENTS_PER_MINUTE = 10 # Max events to trigger bulk detection
MAX_DELETIONS_PER_MINUTE = 5 # Max deletions to trigger bulk deletion detection
ENTROPY_THRESHOLD = 7.0 # Entropy threshold for suspicious files
LOW_ASCII_RATIO = 0.5 # ASCII ratio threshold for suspicious files
SIMILARITY_THRESHOLD = 50 # Fuzzy similarity threshold for suspicious files
WINDOW_ENTROPY_THRESHOLD = 7.8 # Entropy threshold for windowed entropy
WINDOW_SIZE = 1024 # Size of the sliding window for entropy calculation (1KB)
BASE64_MIN_LENGTH = 128
# Per-format absolute entropy thresholds are deliberately conservative. For binary
# formats, changes are judged against the file's own baseline rather than a text threshold.
FORMAT_ENTROPY_THRESHOLDS = {
    "text": 7.0,
    "pdf": 7.95,
    "docx": 7.95,
    "jpeg": 7.95,
    "unknown_binary": 7.95,
}
SUSPICIOUS_EXTENSIONS = [
    ".locked", ".enc", ".encrypted", ".crypt", ".cripto", ".crypto",
    ".pay", ".ransom", ".crinf", ".r5a", ".WNCRY", ".wcry", ".wncrypt",
    ".wncryt", ".wnry", ".wantcrypt", ".cerber", ".zepto", ".thor",
    ".locky", ".aaa", ".zzz", ".ecc", ".exx", ".ezz", ".abc", ".xyz",
    ".pzdc", ".good", ".hush", ".odin", ".ccc", ".herbst", ".sage"
] # List of suspicious file extensions
HONEYPOT_FILES = set() # Set to store honeypot file names
HONEY_COUNT = 3 # Number of honeypot files to create

# Function to calculate entropy of a file
def file_entropy(data):
    # If the data is empty, then there is no entropy
    if not data:
        return 0.0

    freq = defaultdict(int) # Frequency dictionary for byte values

    # Count the frequency of each byte in the data
    for byte in data:
        freq[byte] += 1

    total = len(data) # Total number of bytes in the data

    # Calculate the entropy using Shannon's formula
    return -sum((count / total) * math.log2(count / total) for count in freq.values())

# Function to calculate sliding window entropy
def sliding_entropy_windows(data, window_size=WINDOW_SIZE):
    entropies = SortedDict() # SortedDict to store entropies

    # Iterate over the data in windows of specified size (default is 1KB)
    for i in range(0, len(data), window_size):
        window = data[i:i + window_size] # Get the current window
        entropies[i // window_size] = file_entropy(window) # Calculate entropy for the window

    return entropies

# Function to calculate ASCII ratio
def ascii_ratio(data):
    printable = set(bytes(string.printable, 'ascii')) # Set of printable ASCII characters

    # If the data is empty, return 1.0 (indicating all characters are printable)
    if not data:
        return 1.0

    # Calculate the ratio of printable characters to total characters
    return sum(1 for b in data if b in printable) / len(data)

# Function to check if data is encoded in a specific format (Helper function of detect_encoding())
def is_encoded(data, pattern, decoder):
    try:
        text = data.decode('ascii', errors='ignore') # Decode data to ASCII
        matches = re.findall(pattern, text) # Find all matches of the pattern in the text

        # Check if any of the matches can be decoded
        for chunk in matches:
            try:
                decoder(chunk.encode()) # Attempt to decode the chunk
                return True # Even if one chunk can be decoded, it's enough to return True

            except Exception:
                continue

        # If no matches can be decoded, then it's probably not a valid encoding
        return False

    except:
        return False

# Function to detect encoding of data
def detect_encoding(data):

    # Calculates what part of the text matches an encoding pattern
    def match_ratio(text, pattern):
        matches = re.findall(pattern, text) # Find all matches of the pattern in the text
        total_chars = sum(len(m) for m in matches) # Calculate the overall length of all matches
        return total_chars / len(text) if text else 0

    flags = []
    try:
        text = data.decode('ascii', errors='ignore') # Decode data to ASCII

        # Check for various encoding patterns
        # Base64
        if match_ratio(text, r'[A-Za-z0-9+/=]{16,}') > 0.5:
            flags.append('Base64')

        # Hex
        if match_ratio(text, r'[0-9a-fA-F]{16,}') > 0.5:
            flags.append('Hex')

        # Base32
        if match_ratio(text, r'[A-Z2-7=]{16,}') > 0.5:
            flags.append('Base32')

        # Base85
        if match_ratio(text, r'[!-u]{16,}') > 0.5:
            flags.append('Base85')

        # Quoted-Printable
        if match_ratio(text, r'(=[0-9A-F]{2})+') > 0.5:
            flags.append('Quoted-Printable')

        # URL
        if match_ratio(text, r'%[0-9A-Fa-f]{2}') > 0.5:
            flags.append('URL')

    except Exception:
        pass

    return flags

# Function to calculate fuzzy similarity between the old and new file
def fuzzy_similarity(old_data, new_data):
    try:
        # If the old file is empty, return 100% similarity to avoid marking a new file as suspicious
        if not old_data:
            return 100

        return int(difflib.SequenceMatcher(None, old_data, new_data).ratio() * 100)

    except Exception:
        return 0

# Function to detect if a file is binary or text
def detect_mime_type(path):
    try:
        with open(path, 'rb') as f:
            data = f.read(1024) # Read the first 1KB of the file

        text_chars = bytearray({7,8,9,10,12,13,27} | set(range(0x20, 0x100))) # Set of valid characters in txt files

        # If some characters are still in the data, then it's probably a binary file
        if bool(data.translate(None, text_chars)):
            return "binary"

        # If the data is now empty, then it's a text file
        else:
            return "text"

    except Exception:
        return "unknown"


def get_file_category(path, data=None):
    """Classify supported formats by extension and, where available, file signature."""
    ext = os.path.splitext(path)[1].lower()
    if data is None:
        try:
            with open(path, "rb") as f:
                data = f.read(16)
        except OSError:
            data = b""

    if ext == ".txt":
        return "text"
    if ext == ".pdf":
        return "pdf" if data.startswith(b"%PDF-") else "invalid_pdf"
    if ext == ".docx":
        # DOCX is a ZIP container. This is a lightweight signature check, not full validation.
        return "docx" if data.startswith(b"PK\\x03\\x04") else "invalid_docx"
    if ext in {".jpg", ".jpeg"}:
        return "jpeg" if data.startswith(b"\\xff\\xd8\\xff") else "invalid_jpeg"
    return "unknown_binary" if detect_mime_type(path) == "binary" else "text"


def is_base64_like(data, min_length=BASE64_MIN_LENGTH):
    """Return True for long, strictly valid Base64 text (a heuristic, not proof)."""
    try:
        text = data.decode("ascii").strip()
        compact = re.sub(r"\\s+", "", text)
        if len(compact) < min_length or len(compact) % 4 != 0:
            return False
        if not re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", compact):
            return False
        base64.b64decode(compact, validate=True)
        return True
    except (UnicodeDecodeError, ValueError):
        return False


def format_entropy_suspicious(category, current_entropy, previous_entropy=None):
    """Format-aware entropy rule. High entropy alone is not an alert for compressed formats."""
    if category == "text":
        return current_entropy > FORMAT_ENTROPY_THRESHOLDS["text"]
    if category in {"pdf", "docx", "jpeg", "unknown_binary"}:
        # Compare against that file's baseline; flag large increases, not naturally high entropy.
        return previous_entropy is not None and current_entropy - previous_entropy >= 1.0
    # Invalid file signatures for a known extension are suspicious.
    return category.startswith("invalid_")


# Function to hash a file using SHA-256
def hash_file(path):
    try:
        with open(path, 'rb') as f:
            data = f.read() # Read the entire file
            return hashlib.sha256(data).hexdigest(), data # Return the hash and data

    except:
        return None, None

# Function to create honeypot files
def create_honeypot_files(base_dir, count):

    for i in range(count):
        path = os.path.join(base_dir, f"__HONEY__{i}.txt")

        try:
            with open(path, 'w') as f:
                f.write("This is a honeypot file\n\nTasks are:\n- Detect ransomware activities"
                        "\n- Notify the user about suspicious activity \n\nDO NOT DELETE OR MODIFY")
            print(f"[INFO] Honeypot created at: {path} (overwritten if existed)")
            HONEYPOT_FILES.add(os.path.basename(path)) # Add honeypot file name to the set

        except Exception as e:
            print(f"[ERROR] Failed to create honeypot file {path}: {e}")

# Function to scan initial files in the monitored directory
def scan_initial_files(base_dir, file_hashes, file_types, file_contents, entropy_baselines):
    # Establish per-file baselines before processing subsequent modifications.
    for root, _, files in os.walk(base_dir):
        for file in files:
            path = os.path.join(root, file)
            h, data = hash_file(path)
            if h and data is not None:
                file_hashes[path] = h
                file_types[path] = get_file_category(path, data[:16])
                file_contents[path] = data[:WINDOW_SIZE * 4]
                entropy_baselines[path] = file_entropy(data[:WINDOW_SIZE * 4])

# Class to handle file system events
class RansomwareEventHandler(FileSystemEventHandler):
    def __init__(self):
        self.file_hashes = SortedDict()
        self.file_types = SortedDict()
        self.file_contents = SortedDict()
        self.entropy_maps = {}  # path -> SortedDict of window entropies
        self.entropy_baselines = {}
        self.event_log = deque()
        self.deletion_log = deque()
        scan_initial_files(
            MONITORED_DIR, self.file_hashes, self.file_types,
            self.file_contents, self.entropy_baselines
        )

    # Event handlers for file system events
    # File modified
    def on_modified(self, event):
        if not event.is_directory:
            self.analyze(event.src_path)

    # File created
    def on_created(self, event):
        if not event.is_directory:
            print(f"New file created: {event.src_path}")
            self.analyze(event.src_path)

    # File deleted
    def on_deleted(self, event):
        if not event.is_directory:
            path = event.src_path
            print(f"File deleted: {path}")

            # For bulk deletion detection
            basename = os.path.basename(path)
            now = time.time()
            self.deletion_log.append(now)
            self.cleanup_old_deletions(now)

            # Check if the deleted file is a honeypot
            if basename in HONEYPOT_FILES:
                print(f"[ATTENTION] Honeypot was deleted!")
                print("[RANSOMWARE] This strongly indicates ransomware activity.")
                return

            # Check if too many files were deleted in a short time
            if len(self.deletion_log) > MAX_DELETIONS_PER_MINUTE:
                print(f"[ATTENTION] Mass deletions detected: {len(self.deletion_log)} files deleted in the last minute!")

    # File renamed
    def on_moved(self, event):
        if not event.is_directory:
            print(f"File renamed: {event.src_path} → {event.dest_path}")

            # Check if the renamed file is a honeypot
            if os.path.basename(event.src_path) in HONEYPOT_FILES:
                print(f"[ATTENTION] Honeypot was renamed!")
                print("[RANSOMWARE] This strongly indicates ransomware activity.")

            self.analyze(event.dest_path)

            # Check if the new file name has a suspicious extension
            if any(event.dest_path.endswith(ext) for ext in SUSPICIOUS_EXTENSIONS):
                print(f"Suspicious file rename to: {event.dest_path}")

    # Analyze a change in the file to determine if it is suspicious or legitimate
    def analyze(self, path):
        # Update the event log with the current time
        now = time.time()
        self.event_log.append(now)
        self.cleanup_old_events(now) # Cleanup old events

        # Check if the file exists
        if not os.path.exists(path):
            return

        # Check if the file extension is suspicious
        ext = os.path.splitext(path)[1].lower()
        suspicious = ext in SUSPICIOUS_EXTENSIONS
        if suspicious:
            print(f" ️Suspicious file extension: {path}")

        # Get the file hash and data
        h, data = hash_file(path)
        if h is None or data is None:
            return

        # Comparison of the old and new file
        old_hash = self.file_hashes.get(path)
        old_type = self.file_types.get(path)
        new_type = get_file_category(path, data[:16])
        previous_entropy = self.entropy_baselines.get(path)
        similarity = fuzzy_similarity(self.file_contents.get(path, b""), data[:WINDOW_SIZE * 4])

        # If the hash is new or different, then analyze the file
        if not old_hash or old_hash != h:
            ascii_val = ascii_ratio(data) # Calculate ASCII ratio
            entropy_val = file_entropy(data[:WINDOW_SIZE * 4]) # Calculate entropy for the first 4KB
            enc_flags = detect_encoding(data[:WINDOW_SIZE * 4]) # Existing encoding heuristics
            base64_like = is_base64_like(data[:WINDOW_SIZE * 4])
            if base64_like:
                print("    ├─ Base64-like content detected")
                # Alert on a transition from non-Base64 content to Base64-like content.
                if old_hash and old_type != "text":
                    suspicious = True
                elif old_hash and not is_base64_like(self.file_contents.get(path, b"")):
                    suspicious = True
                # A new Base64 file is logged as a signal, not automatically called ransomware.

            # Calculate the entropy for the sliding window
            new_entropy_map = sliding_entropy_windows(data)
            self.entropy_maps[path] = new_entropy_map

            # Suspicious if:
            # Apply text thresholds only to text files. Compressed formats are naturally
            # high entropy, so compare their entropy against their own previous baseline.
            suspicious |= (
                format_entropy_suspicious(new_type, entropy_val, previous_entropy) or
                (new_type == "text" and ascii_val < LOW_ASCII_RATIO) or
                (new_type == "text" and old_hash is not None and similarity < SIMILARITY_THRESHOLD) or
                (new_type.startswith("invalid_")) or
                (old_type is not None and old_type != new_type)
            )

            print(f"Change detected: {os.path.basename(path)}")
            print(f"    ├─ Printable ASCII ratio: {ascii_val:.2f}, Entropy: {entropy_val:.2f}, Format: {new_type}")
            print(f"    ├─ Fuzzy similarity: {similarity}%")

            if old_type and old_type != new_type:
                print(f"    ├─ File type changed from {old_type} to {new_type}")
                suspicious = True

            print("    └─ {}".format("️ Suspicious content detected" if suspicious else "✅ Legitimate modification"))

            # Update the new status of the file
            self.file_hashes[path] = h
            self.file_types[path] = new_type
            self.file_contents[path] = data[:WINDOW_SIZE * 4]
            self.entropy_baselines[path] = entropy_val

            # If a honeypot file was modified
            if os.path.basename(path) in HONEYPOT_FILES:
                print(f"[ATTENTION] Honeypot was accessed: {path}")
                print("[RANSOMWARE] This strongly indicates ransomware activity.")

        # If too many changes were detected in a short time
        if len(self.event_log) > MAX_EVENTS_PER_MINUTE:
            print(f"[ATTENTION] Mass changes detected: {len(self.event_log)} changes in last minute!")

    # Cleanup old events and deletions
    def cleanup_old_events(self, now):
        while self.event_log and now - self.event_log[0] > 60:
            self.event_log.popleft()

    def cleanup_old_deletions(self, now):
        while self.deletion_log and now - self.deletion_log[0] > 60:
            self.deletion_log.popleft()

def main():
    print(f"[INFO] Monitoring directory: {MONITORED_DIR}")

    if not os.path.exists(MONITORED_DIR):
        print(f"[INFO] Directory '{MONITORED_DIR}' does not exist. Creating it...")

        try:
            os.makedirs(MONITORED_DIR)

        except Exception as e:
            print(f"[ERROR] Failed to create directory '{MONITORED_DIR}': {e}")
            return

    create_honeypot_files(MONITORED_DIR, HONEY_COUNT)
    print("[INFO] Monitoring has started, press CTRL+C to stop.")

    # Watchdog configuration
    event_handler = RansomwareEventHandler()
    observer = Observer()
    observer.schedule(event_handler, path=MONITORED_DIR, recursive=True) # Monitor the directory recursively
    observer.start() # Start the observer

    # Keep the main running, while watchdog runs in the background
    try:
        while True:
            time.sleep(1) # Sleep to prevent high CPU usage

    # Stop the observer on keyboard interrupt (CTRL+C)
    except KeyboardInterrupt:
        observer.stop()

    observer.join() # Wait for the observer to finish

if __name__ == "__main__":
    main()
