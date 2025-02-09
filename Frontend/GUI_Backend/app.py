from flask import Flask, request, jsonify
from flask_cors import CORS  # Import Flask-CORS
import sqlite3
import pandas as pd
import os
import json

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes
DATABASE = "wazuh_dashboard.db"

PROTOCOL_MAP = {
    6: "TCP",
    17: "UDP",
    1: "ICMP"
}

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

# ---------- POST IPs to blacklist/whitelist ----------
@app.route('/api/ips', methods=['POST'])
def add_ip():
    data = request.json
    ip = data.get("ip")
    list_type = data.get("list_type")  # should be "blacklist" or "whitelist"

    if not ip or list_type not in ("blacklist", "whitelist"):
        return jsonify({"error": "Invalid data"}), 400

    conn = get_db_connection()
    conn.execute("INSERT INTO ip_lists (ip, list_type) VALUES (?, ?)", (ip, list_type))
    conn.commit()
    conn.close()
    return jsonify({"message": f"{ip} added to {list_type}"}), 201

# ---------- DELETE IP from blacklist/whitelist ----------
@app.route('/api/ips/<list_type>/<ip>', methods=['DELETE'])
def delete_ip(list_type, ip):
    if list_type not in ("blacklist", "whitelist"):
        return jsonify({"error": "Invalid list type"}), 400

    conn = get_db_connection()
    result = conn.execute("DELETE FROM ip_lists WHERE ip = ? AND list_type = ?", (ip, list_type))
    conn.commit()
    conn.close()

    if result.rowcount == 0:
        return jsonify({"message": f"{ip} not found in {list_type}"}), 404
    return jsonify({"message": f"{ip} removed from {list_type}"}), 200

# ---------- GET blacklisted/whitelisted IPs ----------
@app.route('/api/ips/<list_type>', methods=['GET'])
def get_ips(list_type):
    if list_type not in ("blacklist", "whitelist"):
        return jsonify({"error": "Invalid list type"}), 400

    conn = get_db_connection()
    ips = conn.execute("SELECT ip FROM ip_lists WHERE list_type = ?", (list_type,)).fetchall()
    conn.close()
    return jsonify([row["ip"] for row in ips])

# ---------- POST network logs ----------
@app.route('/api/logs', methods=['POST'])
def post_logs():
    try:
        logs = request.get_json()
        if not isinstance(logs, list):
            logs = [logs]

        conn = get_db_connection()
        for log in logs:
            conn.execute("""
                INSERT INTO logs (
                    flow_id, src_ip, src_port, dst_ip, dst_port,
                    protocol, timestamp, flow_duration, tot_fwd_pkts, tot_bwd_pkts,
                    totlen_fwd_pkts, totlen_bwd_pkts, fwd_pkt_len_max, fwd_pkt_len_min,
                    fwd_pkt_len_mean, fwd_pkt_len_std, bwd_pkt_len_max, bwd_pkt_len_min,
                    bwd_pkt_len_mean, bwd_pkt_len_std, flow_byts_s, flow_pkts_s,
                    flow_iat_mean, flow_iat_std, flow_iat_max, flow_iat_min,
                    label
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                log.get("Flow ID"),
                log.get("Src IP"),
                int(log.get("Src Port", 0)),
                log.get("Dst IP"),
                int(log.get("Dst Port", 0)),
                str(log.get("Protocol")),
                log.get("Timestamp"),
                log.get("Flow Duration"),
                log.get("Tot Fwd Pkts"),
                log.get("Tot Bwd Pkts"),
                log.get("TotLen Fwd Pkts"),
                log.get("TotLen Bwd Pkts"),
                log.get("Fwd Pkt Len Max"),
                log.get("Fwd Pkt Len Min"),
                log.get("Fwd Pkt Len Mean"),
                log.get("Fwd Pkt Len Std"),
                log.get("Bwd Pkt Len Max"),
                log.get("Bwd Pkt Len Min"),
                log.get("Bwd Pkt Len Mean"),
                log.get("Bwd Pkt Len Std"),
                log.get("Flow Byts/s"),
                log.get("Flow Pkts/s"),
                log.get("Flow IAT Mean"),
                log.get("Flow IAT Std"),
                log.get("Flow IAT Max"),
                log.get("Flow IAT Min"),
                log.get("Label")
            ))
        conn.commit()
        conn.close()
        return jsonify({"message": f"{len(logs)} logs inserted"}), 201
    except Exception as e:
        return jsonify({"error": f"Failed to store logs: {e}"}), 500

# ---------- GET logs (Only required columns for frontend) ----------
@app.route('/api/logs', methods=['GET'])
def get_logs():
    try:
        conn = get_db_connection()
        df = pd.read_sql_query("SELECT * FROM logs", conn)
        conn.close()

        if 'timestamp' in df.columns:
            df[['Date', 'Time']] = df['timestamp'].str.extract(r'(\d{2}/\d{2}/\d{4})\s+(.*)')
        else:
            raise ValueError("Timestamp column missing in logs")

        df['Protocol'] = df['protocol'].map(lambda x: PROTOCOL_MAP.get(int(x), str(x)) if str(x).isdigit() else x)

        processed_logs = df[[
            'Date', 'Time', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'Protocol', 'label'
        ]].rename(columns={
            'src_ip': 'Src IP', 'src_port': 'Src Port',
            'dst_ip': 'Dst IP', 'dst_port': 'Dst Port',
            'label': 'Label'
        }).to_dict(orient='records')

        return jsonify(processed_logs)
    except Exception as e:
        print(f"Error processing logs: {e}")
        return jsonify({"error": "Failed to process logs"}), 500

# ---------- Optional: Add user (plaintext for now) ----------
@app.route('/api/users', methods=['POST'])
def add_user():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    try:
        conn = get_db_connection()
        conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
        conn.commit()
        conn.close()
        return jsonify({"message": f"User {username} created"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already exists"}), 409


LOG_JSON_PATH = "alerts.json"

# ---------- GET all Wazuh logs, flattened for dashboard use ----------
@app.route('/api/wazuh/logs', methods=['GET'])
def get_wazuh_logs():
    """
    Read every line in LOG_JSON_PATH, parse it as JSON,
    flatten to the key fields, and return as one big list.
    """
    try:
        out = []
        with open(LOG_JSON_PATH, 'r') as f:
            for line in f:
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    # skip malformed lines
                    continue

                out.append({
                    "id":          entry.get("id"),
                    "timestamp":   entry.get("timestamp"),
                    "agent":       entry.get("agent", {}).get("name"),
                    "rule_id":     entry.get("rule", {}).get("id"),
                    "rule_level":  entry.get("rule", {}).get("level"),
                    "rule_desc":   entry.get("rule", {}).get("description"),
                    "location":    entry.get("location"),
                })

        return jsonify(out), 200

    except FileNotFoundError:
        return jsonify({"error": f"Log file not found at {LOG_JSON_PATH}"}), 404
    except Exception as e:
        return jsonify({"error": f"Failed to read wazuh logs: {e}"}), 500



if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
