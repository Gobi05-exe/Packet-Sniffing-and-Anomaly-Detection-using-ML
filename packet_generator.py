from scapy.all import Raw, IP, TCP, send
import random
import time
import csv
import os
import socket
from datetime import datetime

# Get the actual IP address of the machine
def get_local_ip():
    try:
        # Create a socket connection to a public server to get our outgoing IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        # Fallback to localhost if we can't determine IP
        return "127.0.0.1"

# Get a list of open ports on the local machine
def get_open_ports(max_ports=5):
    open_ports = []
    # Get some standard ports that might be open
    common_ports = [22, 80, 443, 3306, 8080, 5000, 8000]
    
    # Try to find actual open ports
    for port in common_ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.1)
            result = s.connect_ex(('127.0.0.1', port))
            if result == 0:
                open_ports.append(port)
            s.close()
        except:
            pass
    
    # If we couldn't find any open ports, use some common ones
    if not open_ports:
        open_ports = [random.choice([80, 443, 8080])]
    
    # Limit to max_ports
    return open_ports[:max_ports]

# Initialize global variables for local network info
LOCAL_IP = get_local_ip()
NETWORK_PREFIX = '.'.join(LOCAL_IP.split('.')[:3])  # Get the network prefix (e.g., 192.168.1)
OPEN_PORTS = get_open_ports()

INTERFACE = None  # Will be determined automatically by scapy
CSV_FILE = 'generated_packets.csv'

tcp_flags = ['S', 'SA', 'A', 'R', 'PA', 'F', 'P', 'FA']

# Create CSV file and write header if it doesn't exist
def initialize_csv():
    file_exists = os.path.isfile(CSV_FILE)
    with open(CSV_FILE, 'a', newline='') as csvfile:
        fieldnames = ['timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 
                     'flags', 'payload_size', 'land', 'urg_pointer', 'seq', 'ack', 'label']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        if not file_exists:
            writer.writeheader()
    
    print(f"CSV logging initialized. Saving to {CSV_FILE}")
    print(f"Using local IP: {LOCAL_IP}, Network: {NETWORK_PREFIX}.0/24")
    print(f"Detected open ports: {OPEN_PORTS}")

def generate_packet():
    is_anomalous = random.choice([True, False])
    label = "anomalous" if is_anomalous else "normal"

    # Use the actual local IP as source or destination with higher probability
    if random.random() < 0.7:  # 70% chance to use local IP as source
        src_ip = LOCAL_IP
        dst_ip = f"{NETWORK_PREFIX}.{random.randint(1,254)}"
    else:
        src_ip = f"{NETWORK_PREFIX}.{random.randint(1,254)}"
        dst_ip = LOCAL_IP
    
    # Land attack: src == dst
    land = random.choice([1] if is_anomalous else [0])

    if land == 1:
        dst_ip = src_ip

    # Use an actual open port with higher probability
    if random.random() < 0.6:  # 60% chance to use an actual open port
        if random.random() < 0.5:  # as source
            src_port = random.choice(OPEN_PORTS)
            dst_port = random.randint(1024, 65535)
        else:  # as destination
            src_port = random.randint(1024, 65535)
            dst_port = random.choice(OPEN_PORTS)
    else:
        src_port = random.randint(1024, 65535)
        dst_port = random.choice([20, 21, 22, 23, 25, 53, 80, 443, 8080])

    flags = random.choice(tcp_flags if not is_anomalous else ['S', 'F', 'R'])  # SYN/FIN/RESET common in attacks
    urg_flag = 'U' in flags
    urg_pointer = random.randint(1, 100) if is_anomalous and random.random() < 0.3 else 0  # occasional urgent

    seq = random.randint(0, 10000)
    ack = random.randint(0, 10000)

    # Adjust payload sizes to prevent "Message too long" error
    # Maximum payload size for loopback interface is typically around 1000 bytes
    payload_size = random.randint(500, 900) if is_anomalous else random.randint(20, 200)
    payload = Raw(load="X" * payload_size)

    pkt = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port,
                                         flags=flags, seq=seq, ack=ack,
                                         urgptr=urg_pointer)/payload

    # Log packet details to CSV file
    with open(CSV_FILE, 'a', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=['timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 
                                                    'flags', 'payload_size', 'land', 'urg_pointer', 'seq', 'ack', 'label'])
        writer.writerow({
            'timestamp': datetime.now().isoformat(),
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'flags': flags,
            'payload_size': payload_size,
            'land': land,
            'urg_pointer': urg_pointer,
            'seq': seq,
            'ack': ack,
            'label': label
        })

    print(f"Sending [{label}] packet: src={src_ip}:{src_port}, dst={dst_ip}:{dst_port}, flags={flags}, "
          f"payload={payload_size}, land={land}, urg={urg_pointer}")

    return pkt

# Initialize CSV file before starting
initialize_csv()

try:
    print("Starting packet generation. Press CTRL+C to stop.")
    while True:
        try:
            pkt = generate_packet()
            # Use the correct interface for macOS
            send(pkt, verbose=False, iface='lo0')
            time.sleep(random.uniform(0.5, 2))
        except OSError as e:
            if e.errno == 40:  # Message too long error
                print("Packet too large, reducing size and retrying...")
                continue
            else:
                print(f"Error sending packet: {e}")
        except Exception as e:
            print(f"Unexpected error: {e}")
            time.sleep(1)  # Add delay before retrying
except KeyboardInterrupt:
    print("\nPacket generation stopped by user")