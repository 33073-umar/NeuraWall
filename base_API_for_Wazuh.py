import requests
import json

# Wazuh API credentials
WAZUH_API_URL = "https://your-wazuh-server:55000"
WAZUH_USER = "wazuh-wui"
WAZUH_PASS = "your-password"

# Disable SSL warnings (if using self-signed certificates)
requests.packages.urllib3.disable_warnings()

# Function to get alerts from Wazuh API
def get_wazuh_alerts():
    endpoint = f"{WAZUH_API_URL}/security/events"
    headers = {"Content-Type": "application/json"}
    
    # Send API request
    response = requests.get(endpoint, auth=(WAZUH_USER, WAZUH_PASS), headers=headers, verify=False)

    if response.status_code == 200:
        alerts = response.json()
        return alerts
    else:
        print(f"Error: {response.status_code}, {response.text}")
        return None

# Process alerts
def process_alerts(alerts):
    for alert in alerts.get('data', {}).get('events', []):
        print(f"Alert: {alert['rule']['description']}, Severity: {alert['rule']['level']}")
        # Here, you can send alerts to your AI firewall

# Run
if __name__ == "__main__":
    alerts = get_wazuh_alerts()
    if alerts:
        process_alerts(alerts)
