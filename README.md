
# NeuraWall: An AI-Based Firewall

**NeuraWall** is an AI-powered firewall designed to detect and prevent network attacks such as port scanning, DoS, and brute force attacks. This project integrates machine learning models with a robust monitoring pipeline to secure networks in real-time.

---

## **Features**

- **AI-Powered Detection**: Utilizes machine learning models (One-Class SVM and Gradient Boosting) for anomaly and malicious traffic detection.
- **Whitelisting Mechanism**: Allows trusted IPs to be excluded from detection and blocking.
- **Real-Time Traffic Analysis**: Captures and processes live network traffic with Dumpcap and CICFlowMeter.
- **Automated Firewall Updates**: Automatically blocks malicious IPs by updating the Windows Firewall using its API.
- **User-Friendly Interface**: ReactJS and Flask-based GUI to manage logs, blacklisted IPs, and whitelisted IPs.
- **Customizable Modes**:
  - One-Class SVM: Trained on benign traffic for local anomaly detection.
  - Gradient Boosting: Trained on CIC IDS 2017 and 2018 datasets for broader attack detection.

---

## **Getting Started**

### **Prerequisites**
- Python 3.8+
- Node.js 14+
- Wireshark (required for Dumpcap)
- ReactJS

### **Installation**

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/yourusername/NeuraWall.git
   cd NeuraWall
   ```

2. **Backend Setup**:
   - Install Python dependencies:
     ```bash
     pip install -r backend/requirements.txt
     ```
   - Run the Flask server:
     ```bash
     python backend/app.py
     ```

3. **Frontend Setup**:
   - Navigate to the `frontend` directory:
     ```bash
     cd frontend
     ```
   - Install dependencies:
     ```bash
     npm install
     ```
   - Start the React development server:
     ```bash
     npm start
     ```

4. **Pipeline Setup**:
   - The repository includes CICFlowMeter in the `pipeline` folder.
   - Ensure Wireshark is installed for `Dumpcap` to function.

---

## **Usage**

### **Real-Time Detection**
1. Capture network traffic using `dumpcap`.
2. Traffic flows are automatically processed by CICFlowMeter.
3. Analyze the traffic using the machine learning pipeline.
4. Automatically blacklist malicious IPs or whitelist trusted ones.

### **GUI Features**
- View and filter log files.
- Search logs by specific columns and time ranges.
- Manage blacklisted and whitelisted IPs (add/remove as needed).
- Toggle real-time updates.

---

## **Architecture**

1. **Traffic Capture**:
   - Captured with `Dumpcap`.
2. **Feature Extraction**:
   - Extract features using CICFlowMeter (automatically invoked from the pipeline).
3. **AI Detection Pipeline**:
   - One-Class SVM for baseline benign traffic.
   - Gradient Boosting for attack detection.
4. **Firewall Management**:
   - Blacklist malicious IPs and whitelist trusted IPs via Windows Firewall API.
5. **GUI**:
   - Display logs and provide blacklist/whitelist management features.

---

## **Technologies Used**

- **Languages**: Python, JavaScript
- **Frontend**: ReactJS
- **Backend**: Flask
- **Machine Learning**: Scikit-learn
- **Traffic Analysis**: Dumpcap, CICFlowMeter
- **Firewall Management**: Windows Firewall API

---

## **Project Roadmap**

- **Stage 1**:
  - Build the AI pipeline, GUI, and whitelist/blacklist mechanisms.
  - Train models on benign traffic and public datasets.
- **Stage 2** (Future Work):
  - Integrate VPN (pfSense) for traffic decryption.
  - Add Wazuh for enhanced monitoring.

---

## **Challenges Faced**

- Training models with diverse traffic datasets.
- Ensuring real-time performance and low latency.
- Handling false positives in anomaly detection.

---

## **Contributing**

Contributions are welcome! Please open an issue or submit a pull request for enhancements or bug fixes.

---

## **License**

This project is for academic purposes and is not licensed for commercial use.

---

## **Acknowledgments**

- CICFlowMeter and CIC IDS datasets for traffic analysis.
- Open-source tools and frameworks that made this project possible.

---

### **Contact**

For questions or feedback, feel free to reach out at [33073@students.riphah.edu.pk].
