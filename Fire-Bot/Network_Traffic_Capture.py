# Inside Network_Traffic_Capture.py

import requests
import subprocess
import os
import time
import psutil
import matplotlib.pyplot as plt
from scapy.all import *

WIFI_INTERFACE = "Wi-Fi"  # Change this to match the name of your Wi-Fi interface
CAPTURE_FILE = "E:\\Organixed_Bot\\captured_traffic.pcap"

def start_capture(interface, capture_file):
    """
    Function to start capturing network traffic.
    """
    if os.path.exists(capture_file):
        os.remove(capture_file)

    # Construct the dumpcap command
    cmd = ["dumpcap", "-i", interface, "-w", capture_file, "--temp-dir", os.path.dirname(capture_file)]
    print("Executing command:", " ".join(cmd))  # Debugging output
    subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    print(f"Started capturing network traffic on interface {interface}.")
    print(f"Captured traffic will be saved to {capture_file}.")

def stop_capture():
    """
    Function to stop capturing network traffic.
    """
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if 'dumpcap' in proc.info['name']:
                proc.kill()
                print("Stopped capturing network traffic.")
                return
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    print("No dumpcap process found.")

def analyze_pcapng(pcapng_file):
    """
    Function to analyze captured network traffic from a pcapng file.
    """
    try:
        # Read packets from the pcapng file
        packets = rdpcap(pcapng_file)

        # Analyze packets and extract relevant information
        packet_info = []
        for packet in packets:
            info = {}

            # Check if the IP layer is present in the packet
            if IP in packet:
                info["Source IP"] = packet[IP].src
                info["Destination IP"] = packet[IP].dst
            else:
                info["Source IP"] = "Unknown"
                info["Destination IP"] = "Unknown"

            # Extract other relevant information
            # For example, protocol, payload, etc.
            info["Protocol"] = packet.summary().split()[0] if packet.summary() else "Unknown"
            info["Payload"] = len(packet.payload) if packet.haslayer(Raw) else 0

            packet_info.append(info)

        return packet_info
    except Exception as e:
        print(f"An error occurred: {e}")
        return []

def generate_report(packet_info):
    """
    Function to generate a report based on the analyzed network traffic.
    """
    try:
        # Create a bar chart to visualize the protocol distribution
        protocols = [packet["Protocol"] for packet in packet_info]
        protocol_counts = {protocol: protocols.count(protocol) for protocol in set(protocols)}

        plt.figure(figsize=(8, 6))
        plt.bar(protocol_counts.keys(), protocol_counts.values(), color='skyblue')
        plt.xlabel('Protocol')
        plt.ylabel('Count')
        plt.title('Protocol Distribution')
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.show()

        # Create a pie chart to visualize the top talkers
        source_ips = [packet["Source IP"] for packet in packet_info if packet["Source IP"] != "Unknown"]
        source_ip_counts = {ip: source_ips.count(ip) for ip in set(source_ips)}

        sorted_source_ips = sorted(source_ip_counts.items(), key=lambda x: x[1], reverse=True)
        top_talkers = dict(sorted_source_ips[:5])

        plt.figure(figsize=(8, 6))
        plt.pie(top_talkers.values(), labels=top_talkers.keys(), autopct='%1.1f%%', colors=['lightcoral', 'lightskyblue', 'lightgreen', 'gold', 'lightpink'])
        plt.title('Top Talkers')
        plt.axis('equal')
        plt.tight_layout()
        plt.show()
    except Exception as e:
        print(f"An error occurred: {e}")

def perform_capture():
    """
    Function to perform the entire network traffic capture process.
    """
    start_capture(WIFI_INTERFACE, CAPTURE_FILE)
    time.sleep(15)  # Capture for 60 seconds
    stop_capture()

    # Analyze captured traffic and generate report
    packet_info = analyze_pcapng(CAPTURE_FILE)
    generate_report(packet_info)
