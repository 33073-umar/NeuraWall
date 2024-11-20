import os
import subprocess

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

# Step 2: Generate CSV from PCAP using Gradle
def generate_csv(pcap_file, output_dir, gradle_dir):
    base_name = os.path.splitext(os.path.basename(pcap_file))[0]
    csv_file = os.path.join(output_dir, f"{base_name}.pcap_flows.csv")
    
    print("\n=== Step 2: Converting PCAP to CSV ===")
    gradle_command = [
        "gradlew", "executePcapToCsvCli",
        f"-PpcapFile={pcap_file}",
        f"-PoutputDir={output_dir}"
    ]
    
    try:
        result = subprocess.run(gradle_command, cwd=gradle_dir, shell=True, check=True, text=True, capture_output=True)
        relevant_lines = [line for line in result.stdout.splitlines() if any(kw in line for kw in ["Working on", "Done!", "Packets stats", "Flow features generated successfully"])]
        print("\n".join(relevant_lines))
    except subprocess.CalledProcessError as e:
        print("An error occurred while running the gradle command.")
        print("Error output:\n", e.stderr)
    
    return csv_file

# Main Execution Flow
if __name__ == "__main__":
    # Step 1: Capture traffic
    output_dir = os.path.join(os.getcwd(), "network_capture")
    gradle_dir = "CICFlowMeter"
    interface_number = 7  # Replace with actual interface if using get_active_interface()
    pcap_file = capture_traffic_dumpcap(interface_number, output_dir)

    # Step 2: Generate CSV from PCAP
    csv_file = generate_csv(pcap_file, output_dir, gradle_dir)

