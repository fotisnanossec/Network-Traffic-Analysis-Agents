import sys
import os
import subprocess

def analyze_http(pcap_file):
    if not os.path.exists(pcap_file):
        print(f"Error: PCAP file not found at {pcap_file}")
        sys.exit(1)

    print(f"Analyzing HTTP traffic in {pcap_file}...")

    # The tshark command to filter for HTTP and extract specific fields, now including time
    tshark_command = [
        'tshark', '-r', pcap_file,
        '-Y', 'http',
        '-T', 'fields',
        '-e', 'frame.time',
        '-e', 'ip.src',
        '-e', 'ip.dst',
        '-e', 'http.host',
        '-e', 'http.request.full_uri',
        '-e', 'http.user_agent'
    ]

    try:
        # Run tshark and capture its output
        result = subprocess.run(tshark_command, capture_output=True, text=True, check=True)
        http_requests = result.stdout.strip().split('\n')

        if not http_requests or http_requests == ['']:
            print("No HTTP requests found.")
            return

        print("--- HTTP Analysis Results ---")
        for line in http_requests:
            fields = line.split('\t')
            if len(fields) == 6:  # Updated to 6 fields
                timestamp, src_ip, dst_ip, host, uri, user_agent = fields
                print(f"Time: {timestamp}")
                print(f"Source IP: {src_ip} -> Destination IP: {dst_ip}")
                print(f"Host: {host}")
                print(f"URI: {uri}")
                print(f"User-Agent: {user_agent}")
                print("-" * 20)
        
    except FileNotFoundError:
        print("Error: tshark command not found. Make sure Wireshark is installed and in your PATH.")
    except subprocess.CalledProcessError as e:
        print(f"Error running tshark: {e}")
        print(f"Tshark output:\n{e.stderr}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 http_agent.py <pcap_file>")
        sys.exit(1)
    
    pcap_file_path = sys.argv[1]
    analyze_http(pcap_file_path)
