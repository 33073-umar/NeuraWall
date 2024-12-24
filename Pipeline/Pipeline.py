import os
import pandas as pd
import numpy as np
import joblib
import subprocess
import threading
import queue
import time
from subprocess import run, CalledProcessError
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# --- Configuration ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))  # Base directory of the script
OUTPUT_DIR = os.path.join(BASE_DIR, "network_capture")
GRADLE_DIR = "D:\\University\\FYP\\FYP_Final\\Pipeline\\CICFlowMeter"  # Keep CICFlowMeter absolute
LOGS_DIR = os.path.join(BASE_DIR, "logs")
MODEL_DIR = os.path.join(BASE_DIR, 'models')

# --- Traffic Capturing Settings ---
INTERFACE_NUMBER = 4  # Replace with your interface number
DUMP_DURATION = 10  # Duration for each dumpcap capture

# --- Detection Settings ---
ip_malicious_history = {}  # Dictionary to track malicious flow counts per IP
history_window = 6  # Number of CSVs to track
flow_threshold_single = 5  # Threshold for single CSV
flow_threshold_total = 10  # Threshold across history_window CSVs
history_lock = threading.Lock()  # Lock for thread-safe operations

# --- Firewall Settings ---
RULE_PREFIX = "NeuraWall Rule"

# --- Process Queue ---
QUEUE = queue.Queue()  # Shared queue for pcap files

# --- Paths and Files ---
CSV_FILE_PATH = os.path.join(LOGS_DIR, "malicious_ips.csv")
LOG_FILE_PATH = os.path.join(LOGS_DIR, "firewall_log.txt")
WHITELIST_FILE_PATH = os.path.join(LOGS_DIR, "whitelist_ips.csv")
CAPTURED_FILE_PATH = os.path.join(LOGS_DIR, "captured_traffic.csv")
SCALER_FILE_PATH = os.path.join(MODEL_DIR, 'scaler.joblib')
SVM_MODEL_PATH = os.path.join(MODEL_DIR, 'oneclass_svm_model.joblib')
GB_MODEL_PATH = os.path.join(MODEL_DIR, 'gradient_boosting_model.joblib')
FEATURES_FILE_PATH = os.path.join(MODEL_DIR, 'selected_features.joblib')

# --- Directories Setup ---
os.makedirs(LOGS_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(MODEL_DIR, exist_ok=True)


# --- Firewall Rule Management Functions ---
def get_ips_from_csv(file_path):
    """Fetch IPs from the CSV file."""
    if not os.path.exists(file_path) or os.stat(file_path).st_size == 0:
        return set()
    try:
        df = pd.read_csv(file_path, header=None)
        return set(df[0].dropna())
    except Exception:
        return set()  # Return an empty set if the file cannot be parsed or is empty

def get_ips_from_log(file_path):
    """Fetch IPs from the log file."""
    if not os.path.exists(file_path):
        return set()
    try:
        with open(file_path, "r") as log_file:
            return set(line.strip() for line in log_file if line.strip())
    except Exception:
        return set()  # Return an empty set if the log file cannot be read

def block_ip(ip):
    """Block an IP using the firewall."""
    try:
        print(f"Attempting to block IP: {ip}")
        run(f'netsh advfirewall firewall add rule name="{RULE_PREFIX} {ip}" dir=in action=block remoteip={ip}',
            shell=True, check=True, stdout=subprocess.DEVNULL)
        run(f'netsh advfirewall firewall add rule name="{RULE_PREFIX} {ip}" dir=out action=block remoteip={ip}',
            shell=True, check=True, stdout=subprocess.DEVNULL)
        print(f"Successfully blocked IP: {ip}")
        return True
    except CalledProcessError as e:
        print(f"Failed to block IP: {ip}. Error: {e}")
        return False

def unblock_ip(ip):
    """Unblock an IP using the firewall."""
    try:
        print(f"Attempting to unblock IP: {ip}")
        run(f'netsh advfirewall firewall delete rule name="{RULE_PREFIX} {ip}" dir=in',
            shell=True, check=True, stdout=subprocess.DEVNULL)
        run(f'netsh advfirewall firewall delete rule name="{RULE_PREFIX} {ip}" dir=out',
            shell=True, check=True, stdout=subprocess.DEVNULL)
        print(f"Successfully unblocked IP: {ip}")
        return True
    except CalledProcessError as e:
        print(f"Failed to unblock IP: {ip}. Error: {e}")
        return False

def get_ips_from_whitelist(file_path):
    """Fetch IPs from the whitelist file."""
    if not os.path.exists(file_path) or os.stat(file_path).st_size == 0:
        return set()
    try:
        df = pd.read_csv(file_path, header=None)
        return set(df[0].dropna())
    except Exception:
        return set()  # Return an empty set if the file cannot be parsed or is empty

def add_ip_to_whitelist(ip):
    """Add an IP to the whitelist."""
    existing_ips = get_ips_from_whitelist(WHITELIST_FILE_PATH)
    if ip in existing_ips:
        print(f"IP {ip} is already whitelisted.")
        return False
    try:
        with open(WHITELIST_FILE_PATH, "a") as f:
            f.write(f"{ip}\n")
        print(f"Added IP {ip} to whitelist.")
        return True
    except Exception as e:
        print(f"Error adding IP to whitelist: {e}")
        return False

def remove_ip_from_whitelist(ip):
    """Remove an IP from the whitelist."""
    try:
        df = pd.read_csv(WHITELIST_FILE_PATH, header=None)
        df = df[df[0] != ip]
        df.to_csv(WHITELIST_FILE_PATH, index=False, header=False)
        print(f"Removed IP {ip} from whitelist.")
        return True
    except Exception as e:
        print(f"Error removing IP from whitelist: {e}")
        return False

def update_rules():
    """Synchronize the firewall rules and log file with the CSV file."""
    print("Updating firewall rules...")

    # Load current data
    csv_ips = get_ips_from_csv(CSV_FILE_PATH)  # Total IPs
    whitelisted_ips = get_ips_from_whitelist(WHITELIST_FILE_PATH)
    logged_ips = get_ips_from_log(LOG_FILE_PATH)  # Already rule in firewall

    print(f"Loaded IPs from CSV: {csv_ips}")
    print(f"Loaded Whitelisted IPs: {whitelisted_ips}")
    print(f"Loaded Logged IPs: {logged_ips}")

    # Remove whitelisted IPs from CSV IPs
    csv_ips -= whitelisted_ips

    print(f"IPs to be blocked (after removing whitelisted): {csv_ips}")

    # Add new rules for IPs in csv_ips but not in logged_ips
    with open(LOG_FILE_PATH, "a") as log_file:  # Append mode for new IPs
        for ip in csv_ips - logged_ips:
            if block_ip(ip):
                log_file.write(f"{ip}\n")
                print(f"Added rule for IP: {ip}")

    # Remove rules for IPs in logged_ips but not in csv_ips
    for ip in logged_ips - csv_ips:
        if unblock_ip(ip):
            print(f"Removed rule for IP: {ip}")

    # Rewrite the log file with the updated logged_ips
    with open(LOG_FILE_PATH, "w") as log_file:
        for ip in csv_ips:
            log_file.write(f"{ip}\n")

    print("Firewall rules synchronized successfully.")

# --- Watchdog Event Handler ---
class CSVChangeHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if event.src_path.endswith(CSV_FILE_PATH):
            print("CSV file modified. Updating rules...")
            update_rules()

# --- NeuraWall Real-Time Traffic Analysis Functions ---
def capture_traffic(INTERFACE_NUMBER):
    """Continuously capture traffic using dumpcap."""
    file_index = 1
    while True:
        pcap_file = os.path.join(OUTPUT_DIR, f"capture_{file_index}.pcap")
        dumpcap_command = [
            "C:\\Program Files\\Wireshark\\dumpcap.exe",  # Absolute path for dumpcap
            "-i", str(INTERFACE_NUMBER),
            "-a", f"duration:{DUMP_DURATION}",
            "-w", pcap_file
        ]
        try:
            subprocess.run(dumpcap_command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            QUEUE.put(pcap_file)  # Add new pcap file to queue
            file_index += 1
        except subprocess.CalledProcessError:
            pass

def process_pcap_to_csv():
    """Continuously process pcap files to CSV."""
    while True:
        try:
            pcap_file = QUEUE.get()  # Wait for new pcap file
            base_name = os.path.basename(pcap_file)
            csv_file = os.path.join(OUTPUT_DIR, f"{base_name}_flows.csv")  # Expected output file from CICFlowMeter
            gradle_command = [
                os.path.join(GRADLE_DIR, "gradlew.bat"),
                "executePcapToCsvCli",
                f"-PpcapFile={pcap_file}",
                f"-PoutputDir={OUTPUT_DIR}"
            ]
            try:
                subprocess.run(
                    gradle_command, cwd=GRADLE_DIR, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True
                )
                standardize_csv(csv_file)  # Standardize the CSV
                analyze_traffic(csv_file)  # Analyze traffic
                os.remove(pcap_file)  # Delete processed .pcap file
            except subprocess.CalledProcessError:
                pass
        except Exception:
            pass

def standardize_csv(file_path):
    """Standardize the CSV file by renaming columns."""
    column_mapping = {
        "Flow Duration": "Flow Duration",
        "Flow Byts/s": "Flow Bytes/s",
        "Flow Pkts/s": "Flow Packets/s",
        "Tot Fwd Pkts": "Total Fwd Packets",
        "Tot Bwd Pkts": "Total Backward Packets",
        "Pkt Size Avg": "Average Packet Size",
        "Pkt Len Std": "Packet Length Std",
        "Flow IAT Mean": "Flow IAT Mean",
        "Flow IAT Std": "Flow IAT Std",
        "Fwd IAT Mean": "Fwd IAT Mean",
        "Bwd IAT Mean": "Bwd IAT Mean",
        "SYN Flag Cnt": "SYN Flag Count",
        "ACK Flag Cnt": "ACK Flag Count",
        "RST Flag Cnt": "RST Flag Count"
    }
    try:
        data = pd.read_csv(file_path)
        data.columns = data.columns.str.strip()  # Remove whitespace from column names
        standardized_data = data.rename(columns=column_mapping)
        standardized_data.to_csv(file_path, index=False)  # Overwrite the CSV file
    except Exception:
        pass

def analyze_traffic(csv_file):
    """Analyze the traffic in the given CSV file."""
    global ip_malicious_history
    try:
        # Load whitelist
        whitelisted_ips = get_ips_from_whitelist(WHITELIST_FILE_PATH)

        # Load models and configurations
        scaler = joblib.load(SCALER_FILE_PATH)
        svm_model = joblib.load(SVM_MODEL_PATH)
        gb = joblib.load(GB_MODEL_PATH)
        selected_features = joblib.load(FEATURES_FILE_PATH)

        threshold = 0.01  # Threshold for the gradient boosting model

        # Load and preprocess the data
        data = pd.read_csv(csv_file)
        data.columns = data.columns.str.strip()
        data = data.replace([np.inf, -np.inf], np.nan)

        for col in selected_features:
            if col in data.columns:
                data[col] = data[col].fillna(data[col].median())

        # Explicitly label traffic from whitelisted IPs as "Benign"
        data.loc[data['Src IP'].isin(whitelisted_ips), 'Label'] = "Benign"

        # Only apply anomaly detection to traffic with "No Label"
        non_whitelisted_data = data[data['Label'] == "No Label"]

        # Check if non-whitelisted data is empty
        if non_whitelisted_data.empty:
            print("No non-whitelisted traffic to analyze.")
        else:
            X_test = non_whitelisted_data[selected_features].copy()
            X_test_scaled = scaler.transform(X_test)

            # Ensure the required columns exist
            required_columns = ['Flow ID', 'Src IP', 'Src Port', 'Dst IP', 'Dst Port', 'Protocol', 'Timestamp']
            if not all(col in data.columns for col in required_columns):
                raise ValueError("Missing required columns in CSV.")

            # Predict anomalies using SVM and Gradient Boosting
            svm_pred = svm_model.predict(X_test_scaled)
            is_svm_anomaly = (svm_pred == -1)
            gb_anomaly_pred = gb.predict_proba(X_test_scaled[is_svm_anomaly])[:, 1] >= threshold

            # Combine predictions and assign labels
            combined_pred = np.zeros(len(svm_pred), dtype=int)
            combined_pred[is_svm_anomaly] = gb_anomaly_pred.astype(int)
            data.loc[non_whitelisted_data.index, 'Label'] = np.where(combined_pred == 1, "Malicious", "Benign")

        # Identify malicious IPs, excluding whitelisted IPs
        malicious_packets = data[data['Label'] == "Malicious"]
        malicious_ips_series = malicious_packets.groupby('Src IP').size()
        malicious_ips = malicious_ips_series.to_dict()

        # Fetch existing malicious IPs from the CSV
        existing_ips = get_ips_from_csv(CSV_FILE_PATH)

        # Initialize a set to collect IPs to be added
        ips_to_add = set()

        with history_lock:
            # Update ip_malicious_history
            for ip, count in malicious_ips.items():
                if ip in ip_malicious_history:
                    ip_malicious_history[ip].append(count)
                else:
                    ip_malicious_history[ip] = [count]
                # Ensure the history window size
                if len(ip_malicious_history[ip]) > history_window:
                    ip_malicious_history[ip].pop(0)
            # For IPs not in current malicious_ips, append 0
            for ip in list(ip_malicious_history.keys()):
                if ip not in malicious_ips:
                    ip_malicious_history[ip].append(0)
                    if len(ip_malicious_history[ip]) > history_window:
                        ip_malicious_history[ip].pop(0)

            # Now, check for each IP if it meets any of the blocking criteria
            for ip, counts in ip_malicious_history.items():
                total_count = sum(counts)
                max_count = max(counts)
                if (max_count > flow_threshold_single or total_count > flow_threshold_total) and ip not in existing_ips and ip not in whitelisted_ips:
                    ips_to_add.add(ip)

        # Append newly identified malicious IPs to the CSV
        if ips_to_add:
            with open(CSV_FILE_PATH, "a") as f:
                for ip in ips_to_add:
                    print(f"Malicious IP detected (stealth or threshold): {ip}")
                    f.write(f"{ip}\n")

        # Append all rows (labeled) to the captured_traffic.csv
        if not os.path.exists(CAPTURED_FILE_PATH):
            data.to_csv(CAPTURED_FILE_PATH, index=False, mode="w", header=True)  # Create new file with header
        else:
            data.to_csv(CAPTURED_FILE_PATH, index=False, mode="a", header=False)  # Append to existing file without header

        # Delete the original CSV
        os.remove(csv_file)

    except Exception as e:
        print(f"Error analyzing traffic: {e}")

# --- Main Program ---
if __name__ == "__main__":
    print("Starting NeuraWall")

    # Start packet capture and processing threads
    capture_thread = threading.Thread(target=capture_traffic, args=(INTERFACE_NUMBER,), daemon=True)
    process_thread = threading.Thread(target=process_pcap_to_csv, daemon=True)
    capture_thread.start()
    process_thread.start()

    # Set up firewall monitoring
    update_rules()  # Initial synchronization
    event_handler = CSVChangeHandler()
    observer = Observer()
    observer.schedule(event_handler, path=LOGS_DIR, recursive=False)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Stopping NeuraWall.")
        observer.stop()
    observer.join()
