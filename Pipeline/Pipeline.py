import os
import pandas as pd
import numpy as np
import joblib
import subprocess
import threading
import queue
import time

# Configuration
OUTPUT_DIR = os.path.join(os.getcwd(), "network_capture")
GRADLE_DIR = "D:\\University\\FYP\\FYP_Final\\Pipeline\\CICFlowMeter"
LOGS_DIR = os.path.join(os.getcwd(), "logs")
os.makedirs(LOGS_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)

DUMP_DURATION = 10  # Duration for each dumpcap capture
QUEUE = queue.Queue()  # Shared queue for pcap files


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
        except subprocess.CalledProcessError as e:
            pass  # Suppress error messages


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
                pass  # Suppress error messages
        except Exception:
            pass  # Suppress unexpected errors


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
        pass  # Suppress errors during standardization


def analyze_traffic(csv_file):
    """Analyze the traffic in the given CSV file."""
    try:
        # Load the scaler, models, and features
        scaler = joblib.load('models/scaler.joblib')
        svm_model = joblib.load('models/oneclass_svm_model.joblib')
        gb = joblib.load('models/gradient_boosting_model.joblib')
        selected_features = joblib.load('models/selected_features.joblib')

        # Threshold for Gradient Boosting
        threshold = 0.01

        # Load and preprocess the CSV file
        data = pd.read_csv(csv_file)
        data.columns = data.columns.str.strip()
        data = data.replace([np.inf, -np.inf], np.nan)
        for col in selected_features:
            if col in data.columns:
                data[col] = data[col].fillna(data[col].median())
        X_test = data[selected_features].copy()
        X_test_scaled = scaler.transform(X_test)

        # Ensure required columns are present
        required_columns = ['Flow ID', 'Src IP', 'Src Port', 'Dst IP', 'Dst Port', 'Protocol', 'Timestamp']
        if not all(col in data.columns for col in required_columns):
            raise ValueError("Missing required columns in CSV.")

        # Predict using models
        svm_pred = svm_model.predict(X_test_scaled)
        is_svm_anomaly = (svm_pred == -1)
        gb_anomaly_pred = gb.predict_proba(X_test_scaled[is_svm_anomaly])[:, 1] >= threshold

        combined_pred = np.zeros(len(svm_pred), dtype=int)
        combined_pred[is_svm_anomaly] = gb_anomaly_pred.astype(int)

        # Save results
        data['Malicious'] = combined_pred
        malicious_packets = data[data['Malicious'] == 1]
        malicious_ips = malicious_packets.groupby('Src IP').size()

        # Log malicious packets
        if not malicious_packets.empty:
            malicious_packet_file = os.path.join(LOGS_DIR, "malicious_packets.csv")
            malicious_packets[required_columns].to_csv(
                malicious_packet_file,
                mode='a', index=False, header=not os.path.exists(malicious_packet_file)
            )

        # Log malicious IPs with >100 packets
        malicious_ip_file = os.path.join(LOGS_DIR, "malicious_ips.csv")
        with open(malicious_ip_file, "a") as f:
            for ip, count in malicious_ips.items():
                if count > 100:
                    print(f"Malicious IP detected: {ip}")  # Print detected malicious IP
                    f.write(f"{ip}\n")

        # Delete processed CSV after logging
        os.remove(csv_file)

    except Exception:
        pass  # Suppress errors during traffic analysis


if __name__ == "__main__":
    print("Starting NeuraWall")  # Initial message

    interface_number = 7  # Replace with your interface number

    # Create threads for each task
    capture_thread = threading.Thread(target=capture_traffic, args=(interface_number,), daemon=True)
    process_thread = threading.Thread(target=process_pcap_to_csv, daemon=True)

    # Start threads
    capture_thread.start()
    process_thread.start()

    # Keep the main thread running
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Stopping NeuraWall.")
