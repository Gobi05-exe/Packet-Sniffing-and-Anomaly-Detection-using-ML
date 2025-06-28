
# Packet Sniffing and Anomaly Detection Using Machine Learning

## Overview

This project presents a real-time anomaly detection system for network traffic using machine learning. It integrates:

- **Packet Generator** to simulate normal and anomalous TCP traffic  
- **Packet Sniffer** for live packet capture and feature extraction  
- **Random Forest Classifier** for real-time traffic classification  
- **Flask Web Application** for interactive monitoring and system control  

The system utilizes the Scapy library for packet manipulation, scikit-learn for model training, and Flask for an intuitive web dashboard.

---

## Features

- Real-time TCP traffic monitoring and anomaly detection  
- Synthetic generation of diverse normal and malicious packets  
- Machine learning-based traffic classification (Random Forest)  
- Web dashboard to control sniffing, packet generation, and view logs  
- Modular, lightweight, and extensible architecture  

---

## System Components

### 1. Packet Generator (`packet_generator.py`)
- Generates normal and anomalous TCP packets
- Simulates attack behaviors: IP spoofing, port anomalies, TCP flag manipulation, payload variation
- Logs all generated packets to `generated_packets.csv`

### 2. Packet Sniffer (`packet_sniffer.py`)
- Captures live TCP packets using Scapy  
- Extracts relevant features for each packet  
- Applies trained ML model for real-time classification  
- Logs predictions and confidence scores to `detected_packets.csv`

### 3. Model Training (`train.py`)
- Preprocesses KDD Cup dataset with label encoding and class balancing  
- Trains a Random Forest Classifier  
- Saves trained model and encoders for real-time use  

### 4. Flask Web Application (`app.py`)
- Start/Stop packet generator and sniffer  
- View live predictions via RESTful APIs  
- JSON output of captured and classified packets  

---

## Extracted Features

- `duration` - Time since last packet of same flow  
- `protocol_type` - TCP protocol  
- `flag` - TCP flags (SYN, ACK, FIN, etc.)  
- `src_bytes`, `dst_bytes` - Payload sizes  
- `land` - Whether source and destination IP/port are identical  
- `wrong_fragment` - Malformed packet indicator  
- `urgent` - Usage of TCP urgent pointer  
- `count`, `srv_count` - Connection counts from source IP  

---

## Results & Discussion

- High detection accuracy for normal and anomalous traffic  
- Minimal false positives due to balanced dataset  
- Real-time responsiveness with low system overhead  
- User-friendly interface with REST APIs for monitoring  
- Transparent logging for reproducibility and further analysis  

---

## Future Enhancements

- Extend detection to other protocols (UDP, ICMP, encrypted traffic)  
- Enhanced web visualizations and real-time graphs  
- Persistent database storage for logs  
- User authentication for dashboard  
- Potential integration with cloud security or SIEM platforms  

---

## Output

<img width="1395" alt="app1" src="https://github.com/user-attachments/assets/784ea0a7-b746-43ab-a385-41cec7f54fcc" />

<img width="1382" alt="app2" src="https://github.com/user-attachments/assets/66f21471-d2e4-4d18-87d8-7b72a6839726" />

---

## Technical Stack

- Python  
- Scapy  
- scikit-learn  
- Flask  
- Joblib  
- KDD Cup dataset  

---

## Usage

### 1. Train the model:
```bash
python train.py
```

### 2. Start the packet generator:
```bash
python packet_generator.py
```

### 3. Run the sniffer:
```bash
python packet_sniffer.py
```

### 4. Launch the web interface:
```bash
python app.py
```

---

## Logs

- `generated_packets.csv` - All generated packets with labels  
- `detected_packets.csv` - Live traffic predictions and details  

---

## License

This project is for academic and educational purposes.
