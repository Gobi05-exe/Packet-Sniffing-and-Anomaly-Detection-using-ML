from scapy.all import sniff  # Import sniff function
from scapy.layers.inet import IP, TCP  # Explicitly import IP and TCP layers
from collections import defaultdict
import time
import joblib
import pandas as pd
import csv
import os
import sys
import platform
from datetime import datetime

# CSV file to save packet details
CSV_FILE = 'detected_packets.csv'

def get_interface():
    """Get the appropriate interface name based on the operating system"""
    os_type = platform.system().lower()
    if os_type == 'darwin':  # macOS
        return 'lo0'  # Loopback interface for macOS
    elif os_type == 'linux':
        return 'lo'
    else:  # Windows
        return '\\Device\\NPF_Loopback'

def verify_interface(interface):
    """Verify if the interface exists and is available"""
    from scapy.arch import get_if_list
    available_interfaces = get_if_list()
    if interface not in available_interfaces:
        print(f"Available interfaces: {available_interfaces}")
        raise ValueError(f"Interface {interface} not found!")
    return interface

# Load the trained model and encoders
try:
    model = joblib.load('random_forest_model.pkl')
    le_protocol = joblib.load('le_protocol.pkl')
    le_flag = joblib.load('le_flag.pkl')
    print("Successfully loaded ML model and encoders")
except Exception as e:
    print(f"Error loading model or encoders: {e}")
    exit(1)

# Store timestamps to calculate duration
packet_times = {}
ip_connection_count = defaultdict(int)
ip_srv_count = defaultdict(int)

# Initialize CSV file and write header if it doesn't exist
def initialize_csv():
    file_exists = os.path.isfile(CSV_FILE)
    with open(CSV_FILE, 'a', newline='') as csvfile:
        fieldnames = ['timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 
                     'protocol', 'flags', 'duration', 'src_bytes', 'dst_bytes', 
                     'land', 'wrong_fragment', 'urgent', 'count', 'srv_count', 
                     'prediction', 'confidence']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        if not file_exists:
            writer.writeheader()
    
    print(f"CSV logging initialized. Saving to {CSV_FILE}")

def safe_transform(value, encoder, default_value=-1):
    """Safely transform categorical values, handling unseen labels"""
    try:
        if value in encoder.classes_:
            return encoder.transform([value])[0]
        else:
            return default_value
    except Exception as e:
        print(f"Error transforming value {value}: {e}")
        return default_value

def extract_features(pkt):
    if IP in pkt and TCP in pkt:
        # Extract source and destination IP addresses
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        
        # Extract source and destination ports
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
        
        # TCP flags
        flags = pkt[TCP].flags

        # Duration calculation
        flow_key = (src_ip, dst_ip, src_port, dst_port)
        now = time.time()
        duration = now - packet_times.get(flow_key, now)
        packet_times[flow_key] = now

        # Protocol type
        proto = "tcp"

        # Flag
        flag = str(flags)

        # src_bytes and dst_bytes approximation
        src_bytes = len(pkt[TCP].payload)
        dst_bytes = 0  # Simulation as we can't know reply size

        # land feature
        land = int(src_ip == dst_ip)

        # wrong_fragment (simulated)
        wrong_fragment = 0
        if IP in pkt:
            if pkt[IP].flags & 1:  # More fragments flag
                wrong_fragment = 1
            elif pkt[IP].frag != 0:  # Fragment offset
                wrong_fragment = 2

        # urgent
        urgent = int(pkt[TCP].urgptr > 0)

        # count (connections from same src IP)
        ip_connection_count[src_ip] += 1
        count = ip_connection_count[src_ip]

        # srv_count (connections to same dst port from src)
        srv_key = (src_ip, dst_port)
        ip_srv_count[srv_key] += 1
        srv_count = ip_srv_count[srv_key]

        # Create a feature vector as a DataFrame with a single row
        features = {
            'duration': duration,
            'protocol_type': proto,
            'flag': flag,
            'src_bytes': src_bytes,
            'dst_bytes': dst_bytes,
            'land': land,
            'wrong_fragment': wrong_fragment,
            'urgent': urgent,
            'count': count,
            'srv_count': srv_count
        }
        
        # Create a DataFrame for the ML model
        df = pd.DataFrame([features])
        
        # Preprocess the features - same as in train.py
        df['protocol_type'] = df['protocol_type'].apply(lambda x: safe_transform(x, le_protocol))
        df['flag'] = df['flag'].apply(lambda x: safe_transform(x, le_flag))
        
        # Convert all features to numeric and handle missing values
        df = df.apply(pd.to_numeric, errors='coerce').fillna(0)
        
        # Make prediction using the loaded model
        try:
            prediction = model.predict(df)[0]
            prediction_label = "normal" if prediction == 0 else "anomalous"
            
            # Get prediction probability
            prediction_proba = model.predict_proba(df)[0]
            confidence = prediction_proba[prediction]
            
            # Display the results with IP addresses prominently shown
            print(f"\n{'*'*20} PACKET ANALYSIS {'*'*20}")
            print(f"SOURCE: {src_ip}:{src_port} → DESTINATION: {dst_ip}:{dst_port}")
            print(f"TCP Flags: {flag}")
            print(f"Prediction: {prediction_label.upper()} (Confidence: {confidence:.2f})")
            
            # Alert on anomalous traffic with source and destination information
            if prediction == 1:
                print(f"⚠️ ALERT: Potential {prediction_label} traffic detected from {src_ip} to {dst_ip}!")
            
            # Display feature details
            print(f"Full feature set: {features}")
            print(f"{'*'*55}\n")
            
            # Save to CSV file
            with open(CSV_FILE, 'a', newline='') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=[
                    'timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 
                    'protocol', 'flags', 'duration', 'src_bytes', 'dst_bytes', 
                    'land', 'wrong_fragment', 'urgent', 'count', 'srv_count', 
                    'prediction', 'confidence'
                ])
                writer.writerow({
                    'timestamp': datetime.now().isoformat(),
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'protocol': proto,
                    'flags': flag,
                    'duration': duration,
                    'src_bytes': src_bytes,
                    'dst_bytes': dst_bytes,
                    'land': land,
                    'wrong_fragment': wrong_fragment,
                    'urgent': urgent,
                    'count': count,
                    'srv_count': srv_count,
                    'prediction': prediction_label,
                    'confidence': confidence
                })
            
        except Exception as e:
            print(f"Error making prediction: {e}")

# Initialize CSV file before starting sniffing
initialize_csv()

# Start packet capture
print("Starting network traffic monitoring for anomaly detection...")
print("Press Ctrl+C to stop")

try:
    interface = get_interface()
    verified_interface = verify_interface(interface)
    print(f"Using interface: {verified_interface}")
    print("Waiting for packets...")
    
    # Modified sniff parameters to remove verbose flag
    sniff(
        iface=verified_interface,
        prn=extract_features,
        #filter="tcp and (src host localhost or dst host localhost or src host 127.0.0.1 or dst host 127.0.0.1)",
        store=0
    )
except KeyboardInterrupt:
    print("\nMonitoring stopped by user")
except Exception as e:
    print(f"Error during packet capture: {e}")
    print("\nTroubleshooting steps:")
    print("1. Make sure you're running with sudo")
    print("2. Try running the packet generator in another terminal:")
    print("   sudo python3 packet_generator.py")
    print("3. Verify loopback interface is working:")
    print("   sudo tcpdump -i lo0 tcp")
    sys.exit(1)