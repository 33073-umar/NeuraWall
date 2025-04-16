
import sqlite3

conn = sqlite3.connect("wazuh_dashboard.db")
cursor = conn.cursor()

# Table for blacklisted/whitelisted IPs
cursor.execute("""
CREATE TABLE IF NOT EXISTS ip_lists (
    ip TEXT PRIMARY KEY,
    list_type TEXT CHECK(list_type IN ('blacklist', 'whitelist'))
)
""")

# Table for basic users (no password hashing yet)
cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password TEXT
)
""")

# Table for detailed network logs
cursor.execute("""
CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    flow_id TEXT,
    src_ip TEXT,
    src_port INTEGER,
    dst_ip TEXT,
    dst_port INTEGER,
    protocol TEXT,
    timestamp TEXT,
    flow_duration TEXT,
    tot_fwd_pkts TEXT,
    tot_bwd_pkts TEXT,
    totlen_fwd_pkts TEXT,
    totlen_bwd_pkts TEXT,
    fwd_pkt_len_max TEXT,
    fwd_pkt_len_min TEXT,
    fwd_pkt_len_mean TEXT,
    fwd_pkt_len_std TEXT,
    bwd_pkt_len_max TEXT,
    bwd_pkt_len_min TEXT,
    bwd_pkt_len_mean TEXT,
    bwd_pkt_len_std TEXT,
    flow_byts_s TEXT,
    flow_pkts_s TEXT,
    flow_iat_mean TEXT,
    flow_iat_std TEXT,
    flow_iat_max TEXT,
    flow_iat_min TEXT,
    label TEXT
)
""")

conn.commit()
conn.close()
print("✅ Database initialized successfully.")
