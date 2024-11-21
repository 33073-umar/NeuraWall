from flask import Flask, jsonify
import pandas as pd
from flask_cors import CORS

app = Flask(__name__)

# Enable CORS to allow requests from the frontend
CORS(app)

# API endpoint to serve logs from the CSV file
@app.route("/api/logs", methods=["GET"])
def get_logs():
    try:
        csv_file = "logs.csv"  # Ensure the file path is correct
        df = pd.read_csv(csv_file)  # Read the CSV file
        logs = df.to_dict(orient="records")  # Convert to a list of dictionaries
        return jsonify(logs)  # Send JSON response
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True)
