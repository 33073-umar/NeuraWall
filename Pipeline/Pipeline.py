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

# Configuration
OUTPUT_DIR = os.path.join(os.getcwd(), "network_capture")
GRADLE_DIR = "D:\\University\\FYP\\FYP_Final\\Pipeline\\CICFlowMeter"
LOGS_DIR = os.path.join(os.getcwd(), "logs")
os.makedirs(LOGS_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)

DUMP_DURATION = 10  # Duration for each dumpcap capture
QUEUE = queue.Queue()  # Shared queue for pcap files
CSV_FILE_PATH = os.path.join(LOGS_DIR, "malicious_ips.csv")
LOG_FILE_PATH = os.path.join(LOGS_DIR, "firewall_log.txt")
RULE_PREFIX = "NeuraWall Rule"


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
        run(f'netsh advfirewall firewall add rule name="{RULE_PREFIX} {ip}" dir=in action=block remoteip={ip}', shell=True, check=True, stdout=subprocess.DEVNULL)
        run(f'netsh advfirewall firewall add rule name="{RULE_PREFIX} {ip}" dir=out action=block remoteip={ip}', shell=True, check=True, stdout=subprocess.DEVNULL)
        print(f"Blocked IP: {ip}")
        return True
    except CalledProcessError:
        return False


def unblock_ip(ip):
    """Unblock an IP using the firewall."""
    try:
        run(f'netsh advfirewall firewall delete rule name="{RULE_PREFIX} {ip}" dir=in', shell=True, check=True, stdout=subprocess.DEVNULL)
        run(f'netsh advfirewall firewall delete rule name="{RULE_PREFIX} {ip}" dir=out', shell=True, check=True, stdout=subprocess.DEVNULL)
        print(f"Unblocked IP: {ip}")
        return True
    except CalledProcessError:
        return False


def update_rules():
    """Synchronize the firewall rules and log file with the CSV file."""
    csv_ips = get_ips_from_csv(CSV_FILE_PATH)
    logged_ips = get_ips_from_log(LOG_FILE_PATH)

    # Add new rules for IPs in csv_ips but not in logged_ips
    with open(LOG_FILE_PATH, "a") as log_file:  # Append mode for new IPs
        for ip in csv_ips - logged_ips:
            if block_ip(ip):
                log_file.write(f"{ip}\n")

    # Remove rules for IPs in logged_ips but not in csv_ips
    for ip in logged_ips - csv_ips:
        if unblock_ip(ip):
            logged_ips.remove(ip)  # Remove from the logged set

    # Rewrite the log file with the updated logged_ips
    with open(LOG_FILE_PATH, "w") as log_file:
        for ip in csv_ips:
            log_file.write(f"{ip}\n")

    print("Firewall rules synchronized with CSV file.")


# --- Watchdog Event Handler ---

class CSVChangeHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if event.src_path.endswith(CSV_FILE_PATH):
            print("CSV file modified. Updating rules...")
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
    try:
        scaler = joblib.load('models/scaler.joblib')
        svm_model = joblib.load('models/oneclass_svm_model.joblib')
        gb = joblib.load('models/gradient_boosting_model.joblib')
        selected_features = joblib.load('models/selected_features.joblib')

        threshold = 0.01

        data = pd.read_csv(csv_file)
        data.columns = data.columns.str.strip()
        data = data.replace([np.inf, -np.inf], np.nan)
        for col in selected_features:
            if col in data.columns:
                data[col] = data[col].fillna(data[col].median())
        X_test = data[selected_features].copy()
        X_test_scaled = scaler.transform(X_test)

        required_columns = ['Flow ID', 'Src IP', 'Src Port', 'Dst IP', 'Dst Port', 'Protocol', 'Timestamp']
        if not all(col in data.columns for col in required_columns):
            raise ValueError("Missing required columns in CSV.")

        svm_pred = svm_model.predict(X_test_scaled)
        is_svm_anomaly = (svm_pred == -1)
        gb_anomaly_pred = gb.predict_proba(X_test_scaled[is_svm_anomaly])[:, 1] >= threshold

        combined_pred = np.zeros(len(svm_pred), dtype=int)
        combined_pred[is_svm_anomaly] = gb_anomaly_pred.astype(int)

        data['Malicious'] = combined_pred
        malicious_packets = data[data['Malicious'] == 1]
        malicious_ips = malicious_packets.groupby('Src IP').size()

        # Fetch existing IPs from the malicious_ips.csv file
        existing_ips = get_ips_from_csv(CSV_FILE_PATH)

        with open(CSV_FILE_PATH, "a") as f:
            for ip, count in malicious_ips.items():
                if count > 100 and ip not in existing_ips:  # Check if IP is already logged
                    print(f"Malicious IP detected: {ip}")
                    f.write(f"{ip}\n")

        os.remove(csv_file)
    except Exception as e:
        pass


# --- Main Program ---

if __name__ == "__main__":
    print("Starting NeuraWall")

    interface_number = 7  # Replace with your interface number

    # Start packet capture and processing threads
    capture_thread = threading.Thread(target=capture_traffic, args=(interface_number,), daemon=True)
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
