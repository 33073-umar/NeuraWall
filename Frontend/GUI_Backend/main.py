from flask import Flask, jsonify
from flask_cors import CORS
import pandas as pd

app = Flask(__name__)
CORS(app)

# Protocol mapping
PROTOCOL_MAP = {
    6: "TCP",
    17: "UDP",
    1: "ICMP",
    # Add more mappings as needed
}

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
