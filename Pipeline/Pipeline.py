import os
import pandas as pd
import numpy as np
import joblib
import subprocess
import threading
import queue
import time
import requests  # For working with APIs
from subprocess import run, CalledProcessError
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# --- Configuration ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))  # Base directory of the script
OUTPUT_DIR = os.path.join(BASE_DIR, "network_capture")
GRADLE_DIR = "D:\\University\\FYP\\FYP_Final\\Pipeline\\CICFlowMeter"  # Absolute path to CICFlowMeter
LOGS_DIR = os.path.join(BASE_DIR, "logs")
MODEL_DIR = os.path.join(BASE_DIR, 'models')
SERVER_URL = "http://192.168.1.24:5000"  # <<== Update this to your server's URL

# --- Traffic Capturing Settings ---
INTERFACE_NUMBER = 6  # Replace with your interface number
DUMP_DURATION = 10  # Duration for each dumpcap capture

# --- Detection Settings ---
ip_malicious_history = {}  # Dictionary to track malicious flow counts per IP
history_window = 6  # Number of dumps to track
flow_threshold_single = 5  # Threshold for a single dump
flow_threshold_total = 10  # Threshold across history_window dumps
history_lock = threading.Lock()  # Lock for thread-safe operations

# --- Firewall Settings ---
RULE_PREFIX = "NeuraWall Rule"
RULES_UPDATE_INTERVAL = 10  # Seconds interval for periodically updating firewall rules

# --- Process Queue ---
QUEUE = queue.Queue()  # Shared queue for pcap files

# --- Files ---
LOG_FILE_PATH = os.path.join(LOGS_DIR, "firewall_log.txt")

# --- Directories Setup ---
os.makedirs(LOGS_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(MODEL_DIR, exist_ok=True)


# --- API Helper Functions ---
def get_blacklisted_ips():
    """Fetch blacklisted IPs from the API."""
    try:
        response = requests.get(f"{SERVER_URL}/api/ips/blacklist")
        if response.status_code == 200:
            data = response.json()  # Expecting a list of IP addresses
            return set(data)
        else:
            print("Failed to retrieve blacklisted IPs from server.")
    except Exception as e:
        print(f"Exception in get_blacklisted_ips: {e}")
    return set()

def get_whitelisted_ips():
    """Fetch whitelisted IPs from the API."""
    try:
        response = requests.get(f"{SERVER_URL}/api/ips/whitelist")
        if response.status_code == 200:
            data = response.json()  # Expecting a list of IP addresses
            return set(data)
        else:
            print("Failed to retrieve whitelisted IPs from server.")
    except Exception as e:
        print(f"Exception in get_whitelisted_ips: {e}")
    return set()

def add_ip_to_blacklist(ip):
    """Add an IP to the blacklist on the server."""
    try:
        response = requests.post(f"{SERVER_URL}/api/ips", json={"ip": ip, "list_type": "blacklist"})
        if response.status_code in [200, 201]:
            print(f"IP {ip} added to server blacklist.")
            return True
        else:
            print(f"Failed to add IP {ip} to server blacklist. Status Code: {response.status_code}")
    except Exception as e:
        print(f"Exception in add_ip_to_blacklist: {e}")
    return False

def push_log(flow_data):
    """Push a single flow log to the server."""
    try:
        response = requests.post(f"{SERVER_URL}/api/logs", json=flow_data)
        if response.status_code in [200, 201]:
            print("Flow log pushed successfully.")
        else:
            print(f"Failed to push flow log. Status Code: {response.status_code}")
    except Exception as e:
        print(f"Exception in push_log: {e}")


# --- Firewall Rule Management Functions ---
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

def update_rules():
    """Synchronize the firewall rules with the server's blacklisted IPs."""
    print("Updating firewall rules...")

    # Retrieve current data from the server
    blacklisted_ips = get_blacklisted_ips()
    whitelisted_ips = get_whitelisted_ips()

    # Read local log file for currently applied firewall rules (if it exists)
    if os.path.exists(LOG_FILE_PATH):
        try:
            with open(LOG_FILE_PATH, "r") as log_file:
                logged_ips = set(line.strip() for line in log_file if line.strip())
        except Exception:
            logged_ips = set()
    else:
        logged_ips = set()

    print(f"Blacklisted IPs from server: {blacklisted_ips}")
    print(f"Whitelisted IPs from server: {whitelisted_ips}")
    print(f"Currently logged (blocked) IPs: {logged_ips}")

    # Remove whitelisted IPs from the block list
    ips_to_block = blacklisted_ips - whitelisted_ips

    # Add new firewall rules for IPs not yet blocked
    with open(LOG_FILE_PATH, "a") as log_file:
        for ip in ips_to_block - logged_ips:
            if block_ip(ip):
                log_file.write(f"{ip}\n")
                print(f"Added firewall rule for IP: {ip}")

    # Remove firewall rules for IPs that are no longer blacklisted
    for ip in logged_ips - ips_to_block:
        if unblock_ip(ip):
            print(f"Removed firewall rule for IP: {ip}")

    # Rewrite the log file with the updated set of blocked IPs
    with open(LOG_FILE_PATH, "w") as log_file:
        for ip in ips_to_block:
            log_file.write(f"{ip}\n")

    print("Firewall rules synchronized successfully.")

def periodic_update_rules():
    """Periodically update the firewall rules by fetching the latest lists from the server."""
    while True:
        update_rules()
        time.sleep(RULES_UPDATE_INTERVAL)


# --- Watchdog Event Handler ---
class CSVChangeHandler(FileSystemEventHandler):
    def on_modified(self, event):
        # This handler is no longer used to update rules from a CSV.
        # Rules are now managed via API calls.
        pass


# --- NeuraWall Real-Time Traffic Analysis Functions ---
def capture_traffic(interface_number):
    """Continuously capture traffic using dumpcap."""
    file_index = 1
    while True:
        pcap_file = os.path.join(OUTPUT_DIR, f"capture_{file_index}.pcap")
        dumpcap_command = [
            "C:\\Program Files\\Wireshark\\dumpcap.exe",  # Absolute path for dumpcap
            "-i", str(interface_number),
            "-a", f"duration:{DUMP_DURATION}",
            "-w", pcap_file
        ]
        try:
            subprocess.run(dumpcap_command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            QUEUE.put(pcap_file)  # Add new pcap file to processing queue
            file_index += 1
        except subprocess.CalledProcessError:
            pass

def process_pcap_to_csv():
    """Continuously process pcap files to generate flows and analyze traffic."""
    while True:
        try:
            pcap_file = QUEUE.get()  # Wait for a new pcap file
            base_name = os.path.basename(pcap_file)
            csv_file = os.path.join(OUTPUT_DIR, f"{base_name}_flows.csv")  # Output file from CICFlowMeter

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
                analyze_traffic(csv_file)  # Analyze traffic and push flows/logs via API
                os.remove(pcap_file)  # Delete processed pcap file
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
        standardized_data.to_csv(file_path, index=False)  # Overwrite CSV with standardized columns
    except Exception:
        pass

def safe_delete(file_path, retries=5, delay=1):
    """Safely delete a file with retries."""
    for _ in range(retries):
        try:
            os.remove(file_path)
            return True
        except PermissionError:
            time.sleep(delay)
    print(f"Failed to delete {file_path} after {retries} attempts.")
    return False

def analyze_traffic(csv_file):
    """Analyze the traffic in the given CSV file and push flows to the server."""
    global ip_malicious_history
    try:
        # Load whitelisted IPs from the API
        whitelisted_ips = get_whitelisted_ips()

        # Load models and configurations
        scaler = joblib.load(os.path.join(MODEL_DIR, 'scaler.joblib'))
        svm_model = joblib.load(os.path.join(MODEL_DIR, 'oneclass_svm_model.joblib'))
        gb = joblib.load(os.path.join(MODEL_DIR, 'gradient_boosting_model.joblib'))
        selected_features = joblib.load(os.path.join(MODEL_DIR, 'selected_features.joblib'))

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

        if non_whitelisted_data.empty:
            print("No non-whitelisted traffic to analyze.")
        else:
            X_test = non_whitelisted_data[selected_features].copy()
            X_test_scaled = scaler.transform(X_test)

            # Ensure required columns exist
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

        # Identify malicious IPs (excluding whitelisted)
        malicious_packets = data[data['Label'] == "Malicious"]
        malicious_ips_series = malicious_packets.groupby('Src IP').size()
        malicious_ips = malicious_ips_series.to_dict()

        # Retrieve existing blacklisted IPs from the server
        existing_ips = get_blacklisted_ips()

        ips_to_add = set()

        with history_lock:
            # Update ip_malicious_history with current counts
            for ip, count in malicious_ips.items():
                if ip in ip_malicious_history:
                    ip_malicious_history[ip].append(count)
                else:
                    ip_malicious_history[ip] = [count]
                if len(ip_malicious_history[ip]) > history_window:
                    ip_malicious_history[ip].pop(0)
            # Append 0 for IPs not present in current malicious_ips
            for ip in list(ip_malicious_history.keys()):
                if ip not in malicious_ips:
                    ip_malicious_history[ip].append(0)
                    if len(ip_malicious_history[ip]) > history_window:
                        ip_malicious_history[ip].pop(0)

            # Evaluate each IP against the blocking criteria
            for ip, counts in ip_malicious_history.items():
                total_count = sum(counts)
                max_count = max(counts)
                if (max_count > flow_threshold_single or total_count > flow_threshold_total) and ip not in existing_ips and ip not in whitelisted_ips:
                    ips_to_add.add(ip)

        # For each new malicious IP, push it to the server blacklist via API
        for ip in ips_to_add:
            print(f"Malicious IP detected (threshold exceeded): {ip}")
            add_ip_to_blacklist(ip)

        # Push each flow (each row) to the server as a log
        for _, row in data.iterrows():
            flow_data = row.to_dict()
            push_log(flow_data)

        # Delete the temporary CSV file produced by CICFlowMeter
        time.sleep(0.5)
        safe_delete(csv_file)

    except Exception as e:
        print(f"Error analyzing traffic: {e}")
        safe_delete(csv_file)


# --- Main Program ---
if __name__ == "__main__":
    print("Starting NeuraWall")

    # Start packet capture and processing threads
    capture_thread = threading.Thread(target=capture_traffic, args=(INTERFACE_NUMBER,), daemon=True)
    process_thread = threading.Thread(target=process_pcap_to_csv, daemon=True)
    capture_thread.start()
    process_thread.start()

    # Start periodic firewall rules update thread
    rules_update_thread = threading.Thread(target=periodic_update_rules, daemon=True)
    rules_update_thread.start()

    # Initial synchronization of firewall rules
    update_rules()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Stopping NeuraWall.")
