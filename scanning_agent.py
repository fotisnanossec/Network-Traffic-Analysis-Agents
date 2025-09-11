import pyshark
import sys
import os
from collections import defaultdict

def analyze_scanning(pcap_file):
    if not os.path.exists(pcap_file):
        print(f"Error: PCAP file not found at {pcap_file}")
        sys.exit(1)

    print(f"Analyzing for network scanning activity in {pcap_file}...")
    
    # Filter for SYN packets (TCP connect scan) or FIN packets (stealth scan)
    capture = pyshark.FileCapture(pcap_file, display_filter='tcp.flags.syn == 1 or tcp.flags.fin == 1')
    
    scan_attempts = defaultdict(lambda: {'targets': set(), 'ports': set()})

    for packet in capture:
        try:
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            dst_port = packet.tcp.dstport
            
            # A potential scanner is a source IP trying many different ports or destinations
            scan_attempts[src_ip]['targets'].add(dst_ip)
            scan_attempts[src_ip]['ports'].add(dst_port)
            
        except AttributeError:
            continue
            
    if not scan_attempts:
        print("No TCP SYN or FIN packets found.")
        return

    print("--- Potential Scanning Activity ---")
    for ip, data in scan_attempts.items():
        if len(data['ports']) > 10 or len(data['targets']) > 5:
            print(f"Potential Scanner IP: {ip}")
            print(f"  Attempted connections to {len(data['targets'])} unique IPs.")
            print(f"  Attempted connections to {len(data['ports'])} unique ports.")
            print("-" * 20)

    capture.close()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 scanning_agent.py <pcap_file>")
        sys.exit(1)

    pcap_file_path = sys.argv[1]
    analyze_scanning(pcap_file_path)
