import os
import re
import pandas as pd
import numpy as np
import joblib
import subprocess
import threading
import queue
import time
import mysql.connector
from subprocess import run, CalledProcessError
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from flask import Flask, jsonify, request

# --- Database Configuration ---
DB_CONFIG = {
    'user': 'root',
    'password': 'root',  # Replace with your MySQL password
    'host': 'localhost',
    'database': 'neurawall'
}

def get_db_connection():
    return mysql.connector.connect(**DB_CONFIG)

def get_blocked_ips_db():
    """Fetch blocked IPs from the MySQL database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT ip_address FROM blocked_ips")
    ips = {row[0] for row in cursor.fetchall()}
    cursor.close()
    conn.close()
    return ips

def insert_blocked_ip_db(ip):
    """Insert a new blocked IP into the database if it doesn't already exist."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO blocked_ips (ip_address) VALUES (%s)", (ip,))
        conn.commit()
        print(f"Inserted {ip} into blocked_ips table.")
    except mysql.connector.Error as err:
        if err.errno == 1062:
            print(f"IP {ip} already exists in blocked_ips table.")
        else:
            print(f"Error inserting IP {ip}: {err}")
    finally:
        cursor.close()
        conn.close()

def delete_blocked_ip_db(ip):
    """Remove a blocked IP from the database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM blocked_ips WHERE ip_address = %s", (ip,))
        conn.commit()
        print(f"Deleted {ip} from blocked_ips table.")
    except mysql.connector.Error as err:
        print(f"Error deleting IP {ip}: {err}")
    finally:
        cursor.close()
        conn.close()

def get_whitelisted_ips_db():
    """Fetch whitelisted IPs from the MySQL database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT ip_address FROM whitelisted_ips")
    ips = {row[0] for row in cursor.fetchall()}
    cursor.close()
    conn.close()
    return ips

def insert_whitelisted_ip_db(ip):
    """Insert a new whitelisted IP into the database if it doesn't already exist."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO whitelisted_ips (ip_address) VALUES (%s)", (ip,))
        conn.commit()
        print(f"Inserted {ip} into whitelisted_ips table.")
    except mysql.connector.Error as err:
        if err.errno == 1062:
            print(f"IP {ip} already exists in whitelisted_ips table.")
        else:
            print(f"Error inserting IP {ip} into whitelist: {err}")
    finally:
        cursor.close()
        conn.close()

def delete_whitelisted_ip_db(ip):
    """Remove a whitelisted IP from the database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM whitelisted_ips WHERE ip_address = %s", (ip,))
        conn.commit()
        print(f"Deleted {ip} from whitelisted_ips table.")
    except mysql.connector.Error as err:
        print(f"Error deleting IP {ip} from whitelist: {err}")
    finally:
        cursor.close()
        conn.close()

# --- Configuration ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(BASE_DIR, "network_capture")
GRADLE_DIR = "D:\\University\\FYP\\FYP_Final\\Pipeline\\CICFlowMeter"  # Absolute path for CICFlowMeter
LOGS_DIR = os.path.join(BASE_DIR, "logs")
MODEL_DIR = os.path.join(BASE_DIR, "models")

# --- Traffic Capturing Settings ---
INTERFACE_NUMBER = 7  # Replace with your interface number
DUMP_DURATION = 10    # Duration for each dumpcap capture

# --- Detection Settings ---
ip_malicious_history = {}  # Tracks malicious flow counts per IP
history_window = 6         # Number of CSVs to track
flow_threshold_single = 5  # Threshold for a single CSV
flow_threshold_total = 10  # Threshold across CSVs
history_lock = threading.Lock()

# --- Firewall Settings ---
RULE_PREFIX = "NeuraWall Rule"

# --- Process Queue ---
QUEUE = queue.Queue()  # For pcap files

# --- Paths and Files ---
# Note: We no longer use a log file for firewall state.
WHITELIST_FILE_PATH = os.path.join(LOGS_DIR, "whitelist_ips.csv")  # (Legacy; eventually migrate this too)
CAPTURED_FILE_PATH = os.path.join(LOGS_DIR, "captured_traffic.csv")
SCALER_FILE_PATH = os.path.join(MODEL_DIR, "scaler.joblib")
SVM_MODEL_PATH = os.path.join(MODEL_DIR, "oneclass_svm_model.joblib")
GB_MODEL_PATH = os.path.join(MODEL_DIR, "gradient_boosting_model.joblib")
FEATURES_FILE_PATH = os.path.join(MODEL_DIR, "selected_features.joblib")

os.makedirs(LOGS_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(MODEL_DIR, exist_ok=True)

# --- Firewall Rule Management Functions ---
def get_blocked_ips_from_firewall():
    """Query Windows Firewall for rules that match our naming convention and return the set of IPs."""
    try:
        result = subprocess.run('netsh advfirewall firewall show rule name=all',
                                  shell=True, capture_output=True, text=True, check=True)
        pattern = re.compile(rf'{RULE_PREFIX}\s+(\S+)')
        ips = set(pattern.findall(result.stdout))
        return ips
    except Exception as e:
        print(f"Error retrieving firewall rules: {e}")
        return set()

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

# --- Updated Firewall Synchronization Function ---
def update_rules():
    """Synchronize the firewall rules with the database."""
    print("Updating firewall rules...")

    # Get the desired state from the DB
    db_blocked_ips = get_blocked_ips_db()
    db_whitelisted_ips = get_whitelisted_ips_db()
    ips_to_block = db_blocked_ips - db_whitelisted_ips

    # Get the current firewall state by querying Windows Firewall
    firewall_ips = get_blocked_ips_from_firewall()

    print(f"Blocked IPs in DB: {db_blocked_ips}")
    print(f"Whitelisted IPs in DB: {db_whitelisted_ips}")
    print(f"IPs currently blocked in firewall: {firewall_ips}")
    print(f"IPs that should be blocked: {ips_to_block}")

    # Add missing rules
    for ip in ips_to_block:
        if ip not in firewall_ips:
            if block_ip(ip):
                print(f"Added firewall rule for IP: {ip}")

    # Remove extraneous rules
    for ip in firewall_ips:
        if ip not in ips_to_block:
            if unblock_ip(ip):
                print(f"Removed firewall rule for IP: {ip}")

    print("Firewall rules synchronized successfully.")

# --- Optional Legacy Watchdog Handler (if you still update whitelist via file) ---
class CSVChangeHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if event.src_path.endswith(WHITELIST_FILE_PATH):
            print("Legacy whitelist file modified. Triggering update...")
            update_rules()

# --- NeuraWall Real-Time Traffic Analysis Functions ---
def capture_traffic(interface_number):
    """Continuously capture traffic using dumpcap."""
    file_index = 1
    while True:
        pcap_file = os.path.join(OUTPUT_DIR, f"capture_{file_index}.pcap")
        dumpcap_command = [
            "C:\\Program Files\\Wireshark\\dumpcap.exe",
            "-i", str(interface_number),
            "-a", f"duration:{DUMP_DURATION}",
            "-w", pcap_file
        ]
        try:
            subprocess.run(dumpcap_command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            QUEUE.put(pcap_file)
            file_index += 1
        except subprocess.CalledProcessError:
            pass

def process_pcap_to_csv():
    """Continuously process pcap files to CSV."""
    while True:
        try:
            pcap_file = QUEUE.get()
            base_name = os.path.basename(pcap_file)
            csv_file = os.path.join(OUTPUT_DIR, f"{base_name}_flows.csv")
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
                standardize_csv(csv_file)
                analyze_traffic(csv_file)
                os.remove(pcap_file)
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
        data.columns = data.columns.str.strip()
        standardized_data = data.rename(columns=column_mapping)
        standardized_data.to_csv(file_path, index=False)
    except Exception:
        pass

def safe_delete(file_path, retries=5, delay=1):
    for _ in range(retries):
        try:
            os.remove(file_path)
            return True
        except PermissionError:
            time.sleep(delay)
    print(f"Failed to delete {file_path} after {retries} attempts.")
    return False

def analyze_traffic(csv_file):
    """Analyze the traffic in the given CSV file."""
    global ip_malicious_history
    try:
        # For whitelist, we use the DB-based retrieval (you might eventually move legacy CSV whitelist to DB)
        whitelisted_ips = get_whitelisted_ips_db()

        scaler = joblib.load(SCALER_FILE_PATH)
        svm_model = joblib.load(SVM_MODEL_PATH)
        gb = joblib.load(GB_MODEL_PATH)
        selected_features = joblib.load(FEATURES_FILE_PATH)

        threshold = 0.01

        data = pd.read_csv(csv_file)
        data.columns = data.columns.str.strip()
        data = data.replace([np.inf, -np.inf], np.nan)

        for col in selected_features:
            if col in data.columns:
                data[col] = data[col].fillna(data[col].median())

        data.loc[data['Src IP'].isin(whitelisted_ips), 'Label'] = "Benign"
        non_whitelisted_data = data[data['Label'] == "No Label"]

        if non_whitelisted_data.empty:
            print("No non-whitelisted traffic to analyze.")
        else:
            X_test = non_whitelisted_data[selected_features].copy()
            X_test_scaled = scaler.transform(X_test)

            required_columns = ['Flow ID', 'Src IP', 'Src Port', 'Dst IP', 'Dst Port', 'Protocol', 'Timestamp']
            if not all(col in data.columns for col in required_columns):
                raise ValueError("Missing required columns in CSV.")

            svm_pred = svm_model.predict(X_test_scaled)
            is_svm_anomaly = (svm_pred == -1)
            gb_anomaly_pred = gb.predict_proba(X_test_scaled[is_svm_anomaly])[:, 1] >= threshold

            combined_pred = np.zeros(len(svm_pred), dtype=int)
            combined_pred[is_svm_anomaly] = gb_anomaly_pred.astype(int)
            data.loc[non_whitelisted_data.index, 'Label'] = np.where(combined_pred == 1, "Malicious", "Benign")

        malicious_packets = data[data['Label'] == "Malicious"]
        malicious_ips_series = malicious_packets.groupby('Src IP').size()
        malicious_ips = malicious_ips_series.to_dict()

        existing_ips = get_blocked_ips_db()
        ips_to_add = set()

        with history_lock:
            for ip, count in malicious_ips.items():
                if ip in ip_malicious_history:
                    ip_malicious_history[ip].append(count)
                else:
                    ip_malicious_history[ip] = [count]
                if len(ip_malicious_history[ip]) > history_window:
                    ip_malicious_history[ip].pop(0)
            for ip in list(ip_malicious_history.keys()):
                if ip not in malicious_ips:
                    ip_malicious_history[ip].append(0)
                    if len(ip_malicious_history[ip]) > history_window:
                        ip_malicious_history[ip].pop(0)
            for ip, counts in ip_malicious_history.items():
                total_count = sum(counts)
                max_count = max(counts)
                if (max_count > flow_threshold_single or total_count > flow_threshold_total) and ip not in existing_ips and ip not in whitelisted_ips:
                    ips_to_add.add(ip)

        for ip in ips_to_add:
            print(f"Malicious IP detected (stealth or threshold): {ip}")
            insert_blocked_ip_db(ip)

        if not os.path.exists(CAPTURED_FILE_PATH):
            data.to_csv(CAPTURED_FILE_PATH, index=False, mode="w", header=True)
        else:
            data.to_csv(CAPTURED_FILE_PATH, index=False, mode="a", header=False)

        time.sleep(0.5)
        safe_delete(csv_file)

    except Exception as e:
        print(f"Error analyzing traffic: {e}")
        safe_delete(csv_file)

# --- API Endpoint for Immediate Sync ---
app_api = Flask("FirewallAPI")

@app_api.route('/sync_rules', methods=['POST'])
def sync_rules():
    try:
        update_rules()
        return jsonify({"status": "success", "message": "Firewall rules synchronized."})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

def run_api():
    app_api.run(port=5001)

# --- Main Program ---
if __name__ == "__main__":
    print("Starting NeuraWall")

    # Start packet capture and processing threads
    capture_thread = threading.Thread(target=capture_traffic, args=(INTERFACE_NUMBER,), daemon=True)
    process_thread = threading.Thread(target=process_pcap_to_csv, daemon=True)
    capture_thread.start()
    process_thread.start()

    # Optionally, if you're still using the legacy whitelist CSV, start a watchdog observer:
    observer = Observer()
    observer.schedule(CSVChangeHandler(), path=LOGS_DIR, recursive=False)
    observer.start()

    # Start the API server in a separate thread so that it can receive immediate sync triggers
    api_thread = threading.Thread(target=run_api, daemon=True)
    api_thread.start()

    # Optionally, perform an initial sync
    update_rules()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Stopping NeuraWall.")
        observer.stop()
    observer.join()
