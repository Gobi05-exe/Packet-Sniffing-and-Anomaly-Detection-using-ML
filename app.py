from flask import Flask, render_template, jsonify, request
import subprocess
import sys
import os
import ctypes
from threading import Thread
import signal
from datetime import datetime
import csv
import json

app = Flask(__name__)

# Global variables to store process states
sniffer_process = None
generator_process = None

def is_admin():
    """Check if the application is running with admin privileges"""
    try:
        return os.getuid() == 0  # For Unix/Linux/Mac
    except AttributeError:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0  # For Windows

def restart_with_admin():
    """Restart the application with admin privileges"""
    if sys.platform == 'win32':
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join(sys.argv), None, 1
        )
    else:
        args = ['sudo', sys.executable] + sys.argv
        os.execvp('sudo', args)

def read_latest_packets(num_packets=None):  # Changed to accept optional limit
    """Read packets from the CSV file"""
    packets = []
    try:
        with open('detected_packets.csv', 'r') as file:
            reader = csv.DictReader(file)
            packets = list(reader)
            # Only limit if num_packets is specified
            if num_packets:
                packets = packets[-num_packets:]
        return packets
    except Exception as e:
        print(f"Error reading packets: {e}")
        return []

@app.route('/')
def index():
    """Render the main dashboard"""
    return render_template('index.html')

@app.route('/start_sniffer')
def start_sniffer():
    """Start the packet sniffer"""
    global sniffer_process
    if sniffer_process is None or sniffer_process.poll() is not None:
        try:
            sniffer_process = subprocess.Popen(
                [sys.executable, 'packet_sniffer.py'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            return jsonify({'status': 'success', 'message': 'Packet sniffer started'})
        except Exception as e:
            return jsonify({'status': 'error', 'message': f'Error starting sniffer: {str(e)}'})
    return jsonify({'status': 'warning', 'message': 'Packet sniffer is already running'})

@app.route('/stop_sniffer')
def stop_sniffer():
    """Stop the packet sniffer"""
    global sniffer_process
    if sniffer_process and sniffer_process.poll() is None:
        if sys.platform == 'win32':
            subprocess.run(['taskkill', '/F', '/T', '/PID', str(sniffer_process.pid)])
        else:
            os.kill(sniffer_process.pid, signal.SIGTERM)
        sniffer_process = None
        return jsonify({'status': 'success', 'message': 'Packet sniffer stopped'})
    return jsonify({'status': 'warning', 'message': 'Packet sniffer is not running'})

@app.route('/start_generator')
def start_generator():
    """Start the packet generator"""
    global generator_process
    if generator_process is None or generator_process.poll() is not None:
        try:
            generator_process = subprocess.Popen(
                [sys.executable, 'packet_generator.py'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            return jsonify({'status': 'success', 'message': 'Packet generator started'})
        except Exception as e:
            return jsonify({'status': 'error', 'message': f'Error starting generator: {str(e)}'})
    return jsonify({'status': 'warning', 'message': 'Packet generator is already running'})

@app.route('/stop_generator')
def stop_generator():
    """Stop the packet generator"""
    global generator_process
    if generator_process and generator_process.poll() is None:
        if sys.platform == 'win32':
            subprocess.run(['taskkill', '/F', '/T', '/PID', str(generator_process.pid)])
        else:
            os.kill(generator_process.pid, signal.SIGTERM)
        generator_process = None
        return jsonify({'status': 'success', 'message': 'Packet generator stopped'})
    return jsonify({'status': 'warning', 'message': 'Packet generator is not running'})

@app.route('/get_packets')
def get_packets():
    """Get the packets from the CSV file"""
    show_latest = request.args.get('latest', default=False, type=bool)
    packets = read_latest_packets(50 if show_latest else None)  # Only limit if latest=true
    return jsonify(packets)

@app.route('/status')
def get_status():
    """Get the current status of sniffer and generator"""
    sniffer_status = 'running' if sniffer_process and sniffer_process.poll() is None else 'stopped'
    generator_status = 'running' if generator_process and generator_process.poll() is None else 'stopped'
    return jsonify({
        'sniffer': sniffer_status,
        'generator': generator_status
    })

if __name__ == '__main__':
    if not is_admin():
        print("This application requires administrator privileges.")
        restart_with_admin()
    else:
        app.run(debug=True, port=5000)