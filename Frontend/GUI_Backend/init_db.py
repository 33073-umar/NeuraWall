import sqlite3
from werkzeug.security import generate_password_hash

conn = sqlite3.connect("wazuh_dashboard.db")
cursor = conn.cursor()

# ─── Agents Table ─────────────────────────────────────────────────────────────
cursor.execute("""
CREATE TABLE IF NOT EXISTS agents (
    agent_id     TEXT    PRIMARY KEY,
    hostname     TEXT    NOT NULL,
    os           TEXT    NOT NULL,
    os_version   TEXT    NOT NULL,
    machine_guid TEXT    NOT NULL,
    mac_address  TEXT    NOT NULL,
    agent_version TEXT   NOT NULL,
    aes_key      BLOB    NOT NULL,
    last_seen    TEXT
);
""")

# ─── IP Lists Table ───────────────────────────────────────────────────────────
cursor.execute("""
CREATE TABLE IF NOT EXISTS ip_lists (
    ip         TEXT    PRIMARY KEY,
    list_type  TEXT    CHECK(list_type IN ('blacklist', 'whitelist')),
    agent_id   TEXT,
    hostname   TEXT,
    FOREIGN KEY(agent_id) REFERENCES agents(agent_id)
)
""")

# ─── Users Table ──────────────────────────────────────────────────────────────
cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    username   TEXT    PRIMARY KEY,
    password   TEXT    NOT NULL,
    role       TEXT    NOT NULL DEFAULT 'watcher'
)
""")

# ─── Logs Table ───────────────────────────────────────────────────────────────
cursor.execute("""
CREATE TABLE IF NOT EXISTS logs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id        TEXT,
    hostname        TEXT,
    flow_id         TEXT,
    src_ip          TEXT,
    src_port        INTEGER,
    dst_ip          TEXT,
    dst_port        INTEGER,
    protocol        TEXT,
    timestamp       TEXT,
    flow_duration   TEXT,
    tot_fwd_pkts    TEXT,
    tot_bwd_pkts    TEXT,
    totlen_fwd_pkts TEXT,
    totlen_bwd_pkts TEXT,
    fwd_pkt_len_max TEXT,
    fwd_pkt_len_min TEXT,
    fwd_pkt_len_mean TEXT,
    fwd_pkt_len_std  TEXT,
    bwd_pkt_len_max  TEXT,
    bwd_pkt_len_min  TEXT,
    bwd_pkt_len_mean TEXT,
    bwd_pkt_len_std  TEXT,
    flow_byts_s      TEXT,
    flow_pkts_s      TEXT,
    flow_iat_mean    TEXT,
    flow_iat_std     TEXT,
    flow_iat_max     TEXT,
    flow_iat_min     TEXT,
    label            TEXT,
    FOREIGN KEY(agent_id) REFERENCES agents(agent_id)
)
""")

# ─── Insert Admin User ────────────────────────────────────────────────────────
admin_username = "admin"
admin_password = "admin123"  # Change this before going live
hashed_password = generate_password_hash(admin_password)

cursor.execute("SELECT * FROM users WHERE username = ?", (admin_username,))
if cursor.fetchone() is None:
    cursor.execute(
        "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
        (admin_username, hashed_password, "admin")
    )
    print(f"✅ Admin user '{admin_username}' created successfully.")
else:
    print(f"ℹ️ Admin user '{admin_username}' already exists.")

conn.commit()
conn.close()
print("✅ Database initialized successfully with agent tracking.")
