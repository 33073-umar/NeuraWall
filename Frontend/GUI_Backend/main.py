from flask import Flask, jsonify, request
from flask_cors import CORS
import pandas as pd
import os

app = Flask(__name__)
CORS(app)

# Protocol mapping
PROTOCOL_MAP = {
    6: "TCP",
    17: "UDP",
    1: "ICMP",
    # Add more mappings as needed
}

# Determine the base directory (where the script is located)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Construct relative paths for CSV files
MALICIOUS_CSV_FILE_PATH = os.path.join(BASE_DIR, "../../Pipeline/logs/malicious_ips.csv")
WHITELIST_CSV_FILE_PATH = os.path.join(BASE_DIR, "../../Pipeline/logs/whitelist_ips.csv")
CAPTURED_TRAFFIC_CSV_FILE_PATH = os.path.join(BASE_DIR, "../../Pipeline/logs/captured_traffic.csv")

# --- GET Request: Malicious IPs ---
@app.route('/api/malicious_ips', methods=['GET'])
def get_malicious_ips():
    try:
        if not os.path.exists(MALICIOUS_CSV_FILE_PATH) or os.stat(MALICIOUS_CSV_FILE_PATH).st_size == 0:
            return jsonify([])  # Return an empty list if the file doesn't exist or is empty

        df = pd.read_csv(MALICIOUS_CSV_FILE_PATH, header=None, names=['IP'])
        df.dropna(subset=['IP'], inplace=True)
        malicious_ips = df.to_dict(orient='records')

        return jsonify(malicious_ips)
    except Exception as e:
        print(f"Error processing malicious IPs: {e}")
        return jsonify({"error": "Failed to process malicious IPs"}), 500

# --- GET Request: Whitelisted IPs ---
@app.route('/api/whitelist_ips', methods=['GET'])
def get_whitelisted_ips():
    try:
        if not os.path.exists(WHITELIST_CSV_FILE_PATH) or os.stat(WHITELIST_CSV_FILE_PATH).st_size == 0:
            return jsonify([])  # Return an empty list if the file doesn't exist or is empty

        df = pd.read_csv(WHITELIST_CSV_FILE_PATH, header=None, names=['IP'])
        df.dropna(subset=['IP'], inplace=True)
        whitelisted_ips = df.to_dict(orient='records')

        return jsonify(whitelisted_ips)
    except Exception as e:
        print(f"Error processing whitelist IPs: {e}")
        return jsonify({"error": "Failed to process whitelist IPs"}), 500

# --- POST Request: Add Malicious IP ---
@app.route('/api/malicious_ips', methods=['POST'])
def add_malicious_ip():
    try:
        ip_to_add = request.json.get('IP')
        if not ip_to_add:
            return jsonify({"error": "No IP provided"}), 400

        # Ensure the file exists
        if not os.path.exists(MALICIOUS_CSV_FILE_PATH):
            with open(MALICIOUS_CSV_FILE_PATH, 'w') as f:
                f.write("")  # Create an empty file if it doesn't exist

        df = pd.read_csv(MALICIOUS_CSV_FILE_PATH, header=None, names=['IP'])

        # Check if the IP already exists
        if ip_to_add in df['IP'].values:
            return jsonify({"error": "IP already exists"}), 400

        # Append the new IP
        with open(MALICIOUS_CSV_FILE_PATH, 'a') as f:
            f.write(f"{ip_to_add}\n")

        return jsonify({"message": "IP added successfully"}), 201
    except Exception as e:
        print(f"Error adding malicious IP: {e}")
        return jsonify({"error": "Failed to add IP"}), 500

# --- POST Request: Add Whitelist IP ---
@app.route('/api/whitelist_ips', methods=['POST'])
def add_whitelist_ip():
    try:
        ip_to_add = request.json.get('IP')
        if not ip_to_add:
            return jsonify({"error": "No IP provided"}), 400

        # Ensure the file exists
        if not os.path.exists(WHITELIST_CSV_FILE_PATH):
            with open(WHITELIST_CSV_FILE_PATH, 'w') as f:
                f.write("")  # Create an empty file if it doesn't exist

        df = pd.read_csv(WHITELIST_CSV_FILE_PATH, header=None, names=['IP'])

        # Check if the IP already exists
        if ip_to_add in df['IP'].values:
            return jsonify({"error": "IP already exists"}), 400

        # Append the new IP
        with open(WHITELIST_CSV_FILE_PATH, 'a') as f:
            f.write(f"{ip_to_add}\n")

        return jsonify({"message": "IP added successfully"}), 201
    except Exception as e:
        print(f"Error adding whitelist IP: {e}")
        return jsonify({"error": "Failed to add IP"}), 500

# --- DELETE Request: Remove Malicious IP ---
@app.route('/api/malicious_ips/<ip_to_remove>', methods=['DELETE'])
def remove_malicious_ip(ip_to_remove):
    try:
        if not os.path.exists(MALICIOUS_CSV_FILE_PATH) or os.stat(MALICIOUS_CSV_FILE_PATH).st_size == 0:
            return jsonify({"error": "File is empty or missing"}), 400

        df = pd.read_csv(MALICIOUS_CSV_FILE_PATH, header=None, names=['IP'])

        # Check if the IP exists
        if ip_to_remove not in df['IP'].values:
            return jsonify({"error": "IP not found"}), 404

        # Remove the IP
        df = df[df['IP'] != ip_to_remove]
        df.to_csv(MALICIOUS_CSV_FILE_PATH, index=False, header=False)

        return jsonify({"message": "IP removed successfully"}), 200
    except Exception as e:
        print(f"Error removing malicious IP: {e}")
        return jsonify({"error": "Failed to remove IP"}), 500

# --- DELETE Request: Remove Whitelist IP ---
@app.route('/api/whitelist_ips/<ip_to_remove>', methods=['DELETE'])
def remove_whitelist_ip(ip_to_remove):
    try:
        if not os.path.exists(WHITELIST_CSV_FILE_PATH) or os.stat(WHITELIST_CSV_FILE_PATH).st_size == 0:
            return jsonify({"error": "File is empty or missing"}), 400

        df = pd.read_csv(WHITELIST_CSV_FILE_PATH, header=None, names=['IP'])

        # Check if the IP exists
        if ip_to_remove not in df['IP'].values:
            return jsonify({"error": "IP not found"}), 404

        # Remove the IP
        df = df[df['IP'] != ip_to_remove]
        df.to_csv(WHITELIST_CSV_FILE_PATH, index=False, header=False)

        return jsonify({"message": "IP removed successfully"}), 200
    except Exception as e:
        print(f"Error removing whitelist IP: {e}")
        return jsonify({"error": "Failed to remove IP"}), 500

# --- GET Request: Logs ---
@app.route('/api/logs', methods=['GET'])
def get_logs():
    try:
        if not os.path.exists(CAPTURED_TRAFFIC_CSV_FILE_PATH) or os.stat(CAPTURED_TRAFFIC_CSV_FILE_PATH).st_size == 0:
            return jsonify([])

        # Load the CSV file
        df = pd.read_csv(CAPTURED_TRAFFIC_CSV_FILE_PATH)

        # Ensure the Timestamp column exists and split it
        if 'Timestamp' in df.columns:
            df[['Date', 'Time']] = df['Timestamp'].str.extract(r'(\d{2}/\d{2}/\d{4})\s+(.*)')
        else:
            raise ValueError("Timestamp column missing in the CSV file")

        # Drop rows with missing or malformed timestamps
        df.dropna(subset=['Date', 'Time'], inplace=True)

        # Map protocol numbers to protocol names
        df['Protocol'] = df['Protocol'].map(PROTOCOL_MAP).fillna("Unknown")

        # Select and format the required columns, including the 'Label' column
        processed_logs = df[[
            'Date', 'Time', 'Src IP', 'Src Port', 'Dst IP', 'Dst Port', 'Protocol', 'Label'
        ]].to_dict(orient='records')

        return jsonify(processed_logs)
    except Exception as e:
        print(f"Error processing logs: {e}")
        return jsonify({"error": "Failed to process logs"}), 500

if __name__ == "__main__":
    app.run(debug=True)
