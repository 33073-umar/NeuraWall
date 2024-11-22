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

CSV_FILE_PATH = "D:\\University\\FYP\\FYP_Final\\Pipeline\\logs\\malicious_ips.csv"  # Replace with the actual path

# --- GET Request ---
@app.route('/api/malicious_ips', methods=['GET'])
def get_malicious_ips():
    try:
        if not os.path.exists(CSV_FILE_PATH) or os.stat(CSV_FILE_PATH).st_size == 0:
            return jsonify([])  # Return an empty list if the file doesn't exist or is empty

        df = pd.read_csv(CSV_FILE_PATH, header=None, names=['IP'])
        df.dropna(subset=['IP'], inplace=True)
        malicious_ips = df.to_dict(orient='records')

        return jsonify(malicious_ips)
    except Exception as e:
        print(f"Error processing malicious IPs: {e}")
        return jsonify({"error": "Failed to process malicious IPs"}), 500

# --- POST Request: Add IP ---
@app.route('/api/malicious_ips', methods=['POST'])
def add_malicious_ip():
    try:
        ip_to_add = request.json.get('IP')
        if not ip_to_add:
            return jsonify({"error": "No IP provided"}), 400

        # Ensure the file exists
        if not os.path.exists(CSV_FILE_PATH):
            with open(CSV_FILE_PATH, 'w') as f:
                f.write("")  # Create an empty file if it doesn't exist

        df = pd.read_csv(CSV_FILE_PATH, header=None, names=['IP'])

        # Check if the IP already exists
        if ip_to_add in df['IP'].values:
            return jsonify({"error": "IP already exists"}), 400

        # Append the new IP
        with open(CSV_FILE_PATH, 'a') as f:
            f.write(f"{ip_to_add}\n")

        return jsonify({"message": "IP added successfully"}), 201
    except Exception as e:
        print(f"Error adding malicious IP: {e}")
        return jsonify({"error": "Failed to add IP"}), 500

# --- PUT Request: Update IP ---
@app.route('/api/malicious_ips/<old_ip>', methods=['PUT'])
def update_malicious_ip(old_ip):
    try:
        new_ip = request.json.get('IP')
        if not new_ip:
            return jsonify({"error": "No new IP provided"}), 400

        if not os.path.exists(CSV_FILE_PATH) or os.stat(CSV_FILE_PATH).st_size == 0:
            return jsonify({"error": "File is empty or missing"}), 400

        df = pd.read_csv(CSV_FILE_PATH, header=None, names=['IP'])

        # Check if the old IP exists
        if old_ip not in df['IP'].values:
            return jsonify({"error": "Old IP not found"}), 404

        # Update the IP
        df['IP'] = df['IP'].replace(old_ip, new_ip)
        df.to_csv(CSV_FILE_PATH, index=False, header=False)

        return jsonify({"message": "IP updated successfully"}), 200
    except Exception as e:
        print(f"Error updating malicious IP: {e}")
        return jsonify({"error": "Failed to update IP"}), 500

# --- DELETE Request: Remove IP ---
@app.route('/api/malicious_ips/<ip_to_remove>', methods=['DELETE'])
def remove_malicious_ip(ip_to_remove):
    try:
        if not os.path.exists(CSV_FILE_PATH) or os.stat(CSV_FILE_PATH).st_size == 0:
            return jsonify({"error": "File is empty or missing"}), 400

        df = pd.read_csv(CSV_FILE_PATH, header=None, names=['IP'])

        # Check if the IP exists
        if ip_to_remove not in df['IP'].values:
            return jsonify({"error": "IP not found"}), 404

        # Remove the IP
        df = df[df['IP'] != ip_to_remove]
        df.to_csv(CSV_FILE_PATH, index=False, header=False)

        return jsonify({"message": "IP removed successfully"}), 200
    except Exception as e:
        print(f"Error removing malicious IP: {e}")
        return jsonify({"error": "Failed to remove IP"}), 500
@app.route('/api/logs', methods=['GET'])
def get_logs():
    try:
        # Load the CSV file
        csv_file_path = "D:\\University\\FYP\\FYP_Final\\Pipeline\\logs\\captured_traffic.csv"   # Replace with the actual path
        df = pd.read_csv(csv_file_path)

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
