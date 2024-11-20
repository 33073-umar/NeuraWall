import os
# Step 1: Capture traffic using dumpcap
def capture_traffic_dumpcap(interface_number, output_dir, capture_duration=30):
    os.makedirs(output_dir, exist_ok=True)
    pcap_file = os.path.join(output_dir, "captured_traffic.pcap")
    print("\n=== Step 1: Capturing Packets with Dumpcap ===")
    print("Capturing packets using dumpcap...")

    dumpcap_command = [
        "C:\\Program Files\\Wireshark\\dumpcap.exe", "-i", str(interface_number), "-a", f"duration:{capture_duration}",
        "-w", pcap_file
    ]

    try:
        subprocess.run(dumpcap_command, check=True)
        print(f"Packets captured and saved to {pcap_file}")
    except subprocess.CalledProcessError as e:
        print("An error occurred during packet capture with dumpcap.")
        print(e)

    return pcap_file

# Main Execution Flow
if __name__ == "__main__":
    # Step 1: Capture traffic
    output_dir = os.path.join(os.getcwd(), "network_capture")
    interface_number = 7  
    pcap_file = capture_traffic_dumpcap(interface_number, output_dir)
