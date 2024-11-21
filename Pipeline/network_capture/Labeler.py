import pandas as pd

# List of files to process
files = ['captured_traffic.pcap_flows.csv'] #, '30_nmap_scan.csv', '120_nmap_scan.csv', 'ddos_attack.csv']

for file in files:
    # Load each CSV file
    df = pd.read_csv(file)
    
    # Print column names to verify them
    print(f"Columns in {file}:")
    print(df.columns.tolist())  # Print the exact column names for inspection

    # Clean up any leading/trailing whitespace and special characters from column names
    df.columns = df.columns.str.strip().str.replace(r'[^A-Za-z0-9_ ]+', '', regex=True)

    # Print cleaned column names to confirm they are as expected
    print("Cleaned columns:", df.columns.tolist())

    # Apply the labeling condition if columns exist
    if 'Src IP' in df.columns and 'Dst IP' in df.columns:
        df['Label'] = df.apply(lambda row: 'MALICIOUS' if row['Src IP'] == '192.168.1.13' and row['Dst IP'] == '192.168.1.3' else 'BENIGN', axis=1)
    else:
        print(f"Required columns 'Src IP' and/or 'Dst IP' not found in {file}. Skipping labeling.")

    # Save the updated DataFrame to a new file with '_labeled' appended to the original file name
    output_file = file.replace('.csv', '_labeled.csv')
    df.to_csv(output_file, index=False)
    
    print(f"Labels have been successfully added for {file} and saved as {output_file}.")
