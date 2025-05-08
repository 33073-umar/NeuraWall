from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import uuid
from datetime import datetime
import pandas as pd
import json
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
REG_TOKEN = os.environ.get("AGENT_REG_TOKEN")
print(REG_TOKEN)
CORS(app)

DATABASE = "wazuh_dashboard.db"
PROTOCOL_MAP = {6: "TCP", 17: "UDP", 1: "ICMP"}
ONLINE_THRESHOLD = 120  # seconds


def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn



def update_agent_last_seen(conn, agent_id):
    now = datetime.utcnow().isoformat()
    conn.execute(
        "UPDATE agents SET last_seen = ? WHERE agent_id = ?",
        (now, agent_id)
    )


# ─── Registration Endpoint ───────────────────────────────────────────────────
@app.route('/api/register', methods=['POST'])
def register_agent():
    data = request.get_json() or {}

    # ─── 1) REQUIRED FIELDS ─────────────────────────────────────────────────────
    hostname = data.get("hostname")
    mac_addr = data.get("mac_address")
    if not hostname or not mac_addr:
        return jsonify({"error": "hostname and mac_address required"}), 400

    # ─── DEBUG LOGGING ─────────────────────────────────────────────────────────
    received_token = data.get("auth_token")
    print(f"[DEBUG] auth_token received={received_token!r}, expected={REG_TOKEN!r}")
    # ─── AUTH CHECK ───────────────────────────────────────────────────────────
    if received_token != REG_TOKEN:
        return jsonify({"error": "unauthorized"}), 403


    # ─── 3) LOOK FOR EXISTING AGENT ────────────────────────────────────────────
    conn   = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT agent_id, is_active FROM agents WHERE mac_address = ?",
        (mac_addr,)
    )
    existing = cursor.fetchone()
    now = datetime.utcnow().isoformat()

    if existing:
        agent_id, is_active = existing["agent_id"], existing["is_active"]
        conn.close()
        if not is_active:
            print(f"[DEBUG] Agent {agent_id} is blocked (is_active=0)")
            return jsonify({"error": "agent blocked"}), 403

        # Update metadata + last_seen
        conn   = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE agents
               SET hostname       = ?,
                   os             = ?,
                   os_version     = ?,
                   platform       = ?,
                   architecture   = ?,
                   processor      = ?,
                   cpu_count      = ?,
                   ip_address     = ?,
                   python_version = ?,
                   last_seen      = ?
             WHERE agent_id = ?
        """, (
            hostname,
            data.get("os"),
            data.get("os_version"),
            data.get("platform"),
            data.get("architecture"),
            data.get("processor"),
            data.get("cpu_count"),
            data.get("ip_address"),
            data.get("python_version"),
            now,
            agent_id
        ))
        conn.commit()
        conn.close()
        return jsonify({"agent_id": agent_id}), 200

    # ─── 4) INSERT NEW AGENT ───────────────────────────────────────────────────
    new_id = str(uuid.uuid4())
    cursor.execute("""
        INSERT INTO agents (
            agent_id, hostname, os, os_version, platform,
            architecture, processor, cpu_count,
            mac_address, ip_address, python_version,
            last_seen, is_active
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
    """, (
        new_id,
        hostname,
        data.get("os"),
        data.get("os_version"),
        data.get("platform"),
        data.get("architecture"),
        data.get("processor"),
        data.get("cpu_count"),
        mac_addr,
        data.get("ip_address"),
        data.get("python_version"),
        now
    ))
    conn.commit()
    conn.close()
    return jsonify({"agent_id": new_id}), 201


@app.route('/api/validate', methods=['POST'])
def validate_agent():
    data = request.get_json() or {}
    agent_id = data.get("agent_id")
    if not agent_id:
        return jsonify({"error": "agent_id required"}), 400

    conn   = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT is_active FROM agents WHERE agent_id = ?",
        (agent_id,)
    )
    row = cursor.fetchone()
    conn.close()

    if not row:
        return jsonify({"error": "agent not found"}), 404
    if not row["is_active"]:
        return jsonify({"error": "agent blocked"}), 403

    return jsonify({"status": "ok"}), 200




# ─── IPs Endpoints ────────────────────────────────────────────────────────────
@app.route('/api/ips', methods=['POST'])
def add_ip():
    data = request.get_json() or {}
    ip = data.get("ip")
    list_type = data.get("list_type")
    agent_id = data.get("agent_id")
    hostname = data.get("hostname")

    if not ip or list_type not in ("blacklist", "whitelist") \
       or not agent_id or not hostname:
        return jsonify({"error": "Invalid data"}), 400

    conn = get_db_connection()
    update_agent_last_seen(conn, agent_id)

    conn.execute("""
        INSERT OR REPLACE INTO ip_lists (ip, list_type, agent_id, hostname)
        VALUES (?, ?, ?, ?)
    """, (ip, list_type, agent_id, hostname))
    conn.commit()
    conn.close()
    return jsonify({"message": f"{ip} added to {list_type}"}), 201


@app.route('/api/ips/<list_type>/<ip>', methods=['DELETE'])
def delete_ip(list_type, ip):
    agent_id = request.args.get("agent_id")
    hostname = request.args.get("hostname")
    if list_type not in ("blacklist", "whitelist") or not agent_id or not hostname:
        return jsonify({"error": "Invalid parameters"}), 400

    conn = get_db_connection()
    update_agent_last_seen(conn, agent_id)

    res = conn.execute(
        "DELETE FROM ip_lists WHERE ip = ? AND list_type = ?",
        (ip, list_type)
    )
    conn.commit()
    conn.close()

    if res.rowcount == 0:
        return jsonify({"message": f"{ip} not found in {list_type}"}), 404
    return jsonify({"message": f"{ip} removed from {list_type}"}), 200


@app.route('/api/ips/<list_type>', methods=['GET'])
def get_ips(list_type):
    agent_id = request.args.get("agent_id")
    hostname = request.args.get("hostname")
    if list_type not in ("blacklist", "whitelist") or not agent_id or not hostname:
        return jsonify({"error": "Invalid parameters"}), 400

    conn = get_db_connection()
    update_agent_last_seen(conn, agent_id)

    rows = conn.execute(
        "SELECT ip FROM ip_lists WHERE list_type = ?",
        (list_type,)
    ).fetchall()
    conn.commit()
    conn.close()
    return jsonify([r["ip"] for r in rows])


# ─── Logs Endpoints ───────────────────────────────────────────────────────────
@app.route('/api/logs', methods=['POST'])
def post_logs():
    try:
        payload = request.get_json()
        logs = payload if isinstance(payload, list) else [payload]
        conn = get_db_connection()

        for log in logs:
            agent_id = log.get("agent_id")
            hostname = log.get("hostname")
            if not agent_id or not hostname:
                return jsonify({"error": "Missing agent metadata"}), 400

            update_agent_last_seen(conn, agent_id)
            conn.execute("""
                INSERT INTO logs (
                    agent_id, hostname,
                    flow_id, src_ip, src_port, dst_ip, dst_port,
                    protocol, timestamp, flow_duration,
                    tot_fwd_pkts, tot_bwd_pkts, totlen_fwd_pkts, totlen_bwd_pkts,
                    fwd_pkt_len_max, fwd_pkt_len_min, fwd_pkt_len_mean, fwd_pkt_len_std,
                    bwd_pkt_len_max, bwd_pkt_len_min, bwd_pkt_len_mean, bwd_pkt_len_std,
                    flow_byts_s, flow_pkts_s, flow_iat_mean, flow_iat_std,
                    flow_iat_max, flow_iat_min, label
                ) VALUES (
                    ?, ?,
                    ?, ?, ?, ?, ?,
                    ?, ?, ?,
                    ?, ?, ?, ?,
                    ?, ?, ?, ?,
                    ?, ?, ?, ?,
                    ?, ?, ?, ?,
                    ?, ?, ?
                )
            """, (
                agent_id, hostname,
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


@app.route('/api/logs', methods=['GET'])
def get_logs():
    try:
        conn = get_db_connection()
        df = pd.read_sql_query("SELECT * FROM logs", conn)
        conn.close()

        df[['Date', 'Time']] = df['timestamp'].str.extract(r'(\d{2}/\d{2}/\d{4})\s+(.*)')
        df['Protocol'] = df['protocol'].map(
            lambda x: PROTOCOL_MAP.get(int(x), str(x)) if str(x).isdigit() else x
        )

        out = df[[
            'Date', 'Time', 'hostname', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'Protocol', 'label'
        ]].rename(columns={
            'hostname': 'Agent',
            'src_ip': 'Src IP',
            'src_port': 'Src Port',
            'dst_ip': 'Dst IP',
            'dst_port': 'Dst Port',
            'label': 'Label'
        }).to_dict(orient='records')

        return jsonify(out)
    except Exception as e:
        print(f"Error in GET /api/logs: {e}")
        return jsonify({"error": "Failed to process logs"}), 500

@app.route('/api/logs_full', methods=['GET'])
def get_logs_full():
    try:
        conn = get_db_connection()
        cursor = conn.execute(
            'SELECT * FROM logs ORDER BY timestamp DESC LIMIT 1000'
        )
        rows = cursor.fetchall()
        conn.close()

        # convert rows to dicts
        logs = [dict(row) for row in rows]
        return jsonify(logs), 200
    except Exception as e:
        return jsonify({'error': f'Failed to fetch logs: {e}'}), 500

# ─── Agents Endpoints ─────────────────────────────────────────────────────────
@app.route('/api/agents', methods=['GET'])
def get_agents():
    conn = get_db_connection()
    rows = conn.execute("SELECT * FROM agents").fetchall()
    conn.close()

    now = datetime.utcnow()
    agent_list = []
    for row in rows:
        last_seen_str = row['last_seen']
        try:
            last_seen_dt = datetime.fromisoformat(last_seen_str)
        except (TypeError, ValueError):
            last_seen_dt = None

        status = 'offline'
        if last_seen_dt and (now - last_seen_dt).total_seconds() < ONLINE_THRESHOLD:
            status = 'online'

        agent_list.append({
            'agent_id':       row['agent_id'],
            'hostname':       row['hostname'],
            'os':             row['os'],
            'os_version':     row['os_version'],
            'platform':       row['platform'],
            'architecture':   row['architecture'],
            'processor':      row['processor'],
            'cpu_count':      row['cpu_count'],
            'mac_address':    row['mac_address'],
            'ip_address':     row['ip_address'],
            'python_version': row['python_version'],
            'last_seen':      last_seen_str,
            'status':         status,
            'is_active':      bool(row['is_active'])
        })

    return jsonify(agent_list), 200

@app.route('/api/agents/<agent_id>/active', methods=['PATCH'])
def set_agent_active(agent_id):
    data = request.get_json() or {}
    # Validate payload
    if 'is_active' not in data or not isinstance(data['is_active'], bool):
        return jsonify({"error": "is_active (boolean) required"}), 400

    new_state = 1 if data['is_active'] else 0

    conn   = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE agents SET is_active = ? WHERE agent_id = ?",
        (new_state, agent_id)
    )
    if cursor.rowcount == 0:
        conn.close()
        return jsonify({"error": "agent not found"}), 404

    conn.commit()
    conn.close()
    return jsonify({
        "agent_id": agent_id,
        "is_active": data['is_active']
    }), 200

"""
@app.route('/api/agents/<agent_id>', methods=['DELETE'])
def delete_agent(agent_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    existing = cursor.execute("SELECT * FROM agents WHERE agent_id = ?", (agent_id,)).fetchone()
    if not existing:
        conn.close()
        return jsonify({"error": "Agent not found"}), 404

    cursor.execute("DELETE FROM logs WHERE agent_id = ?", (agent_id,))
    cursor.execute("DELETE FROM ip_lists WHERE agent_id = ?", (agent_id,))
    cursor.execute("DELETE FROM agents WHERE agent_id = ?", (agent_id,))
    conn.commit()
    conn.close()
    return jsonify({"message": f"Agent {agent_id} deleted"}), 200
"""

# ─── User Authentication & Management ──────────────────────────────────────────
# Helper to fetch authenticated user
def get_user_from_auth():
    auth = request.authorization
    if not auth:
        return None
    conn = get_db_connection()
    user = conn.execute(
        "SELECT username, password, role FROM users WHERE username = ?", 
        (auth.username,)
    ).fetchone()
    conn.close()
    if not user or not check_password_hash(user['password'], auth.password):
        return None
    return user

# Decorator to enforce admin-only access
def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        user = get_user_from_auth()
        if not user:
            return jsonify({"error": "Authentication required"}), 401
        if user['role'] != 'admin':
            return jsonify({"error": "Admin privileges required"}), 403
        return f(*args, **kwargs)
    return wrapper

# ─── Login Endpoint ───────────────────────────────────────────────────────────
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    conn = get_db_connection()
    user = conn.execute(
        "SELECT username, password, role FROM users WHERE username = ?", 
        (username,)
    ).fetchone()
    conn.close()

    if not user or not check_password_hash(user['password'], password):
        return jsonify({"error": "Invalid credentials"}), 401

    return jsonify({"username": user['username'], "role": user['role']}), 200

# ─── List Users (all roles can view) ───────────────────────────────────────────
@app.route('/api/users', methods=['GET'])
def list_users():
    user = get_user_from_auth()
    if not user:
        return jsonify({"error": "Authentication required"}), 401
    conn = get_db_connection()
    rows = conn.execute("SELECT username, role FROM users").fetchall()
    conn.close()
    return jsonify([
        {"username": r['username'], "role": r['role']} for r in rows
    ]), 200

# ─── Create User (admin only) ─────────────────────────────────────────────────
@app.route('/api/users', methods=['POST'])
@admin_required
def create_user():
    data = request.get_json() or {}
    username = data.get("username")
    password = data.get("password")
    role = data.get("role", "watcher")

    if not username or not password or role not in ("admin", "watcher"):
        return jsonify({"error": "Invalid data"}), 400

    hashed = generate_password_hash(password)
    try:
        conn = get_db_connection()
        conn.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            (username, hashed, role)
        )
        conn.commit()
        conn.close()
        return jsonify({"message": f"User {username} created with role {role}"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already exists"}), 409

# ─── Update User (admin only) ─────────────────────────────────────────────────
@app.route('/api/users/<username>', methods=['PUT'])
@admin_required
def update_user(username):
    data = request.get_json() or {}
    password = data.get("password")
    role = data.get("role")

    if not password and not role:
        return jsonify({"error": "Nothing to update"}), 400

    updates = []
    params = []
    if password:
        updates.append("password = ?")
        params.append(generate_password_hash(password))
    if role:
        if role not in ("admin", "watcher"):
            return jsonify({"error": "Invalid role"}), 400
        updates.append("role = ?")
        params.append(role)
    params.append(username)

    conn = get_db_connection()
    res = conn.execute(
        f"UPDATE users SET {', '.join(updates)} WHERE username = ?", params
    )
    conn.commit()
    conn.close()

    if res.rowcount == 0:
        return jsonify({"error": "User not found"}), 404
    return jsonify({"message": f"User {username} updated"}), 200

# ─── Delete User (admin only) ─────────────────────────────────────────────────
@app.route('/api/users/<username>', methods=['DELETE'])
@admin_required
def delete_user(username):
    conn = get_db_connection()
    res = conn.execute(
        "DELETE FROM users WHERE username = ?", (username,)
    )
    conn.commit()
    conn.close()

    if res.rowcount == 0:
        return jsonify({"error": "User not found"}), 404
    return jsonify({"message": f"User {username} deleted"}), 200


LOG_DIR = "/path/to/wazuh/logs"  # Set this to the base directory where Wazuh generates logs

def find_latest_log_file(directory):
    latest_file = None
    latest_mtime = 0
    for root, _, files in os.walk(directory):
        for fname in files:
            fpath = os.path.join(root, fname)
            try:
                mtime = os.path.getmtime(fpath)
                if mtime > latest_mtime:
                    latest_mtime = mtime
                    latest_file = fpath
            except OSError:
                continue
    return latest_file

@app.route('/api/wazuh/logs', methods=['GET'])
def get_wazuh_logs():
    try:
        latest_log_path = find_latest_log_file(LOG_DIR)
        if not latest_log_path:
            return jsonify({"error": "No log files found"}), 404

        out = []
        with open(latest_log_path, 'r') as f:
            for line in f:
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                out.append({
                    "id":         entry.get("id"),
                    "timestamp":  entry.get("timestamp"),
                    "agent":      entry.get("agent", {}).get("name"),
                    "rule_id":    entry.get("rule", {}).get("id"),
                    "rule_level": entry.get("rule", {}).get("level"),
                    "rule_desc":  entry.get("rule", {}).get("description"),
                    "location":   entry.get("location"),
                })
        return jsonify(out), 200

    except Exception as e:
        return jsonify({"error": f"Failed to read wazuh logs: {e}"}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000,ssl_context=("server.crt", "server.key"))
