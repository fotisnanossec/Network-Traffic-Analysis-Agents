import sys
import os
import subprocess
from collections import defaultdict

def analyze_dns(pcap_file):
    if not os.path.exists(pcap_file):
        print(f"Error: PCAP file not found at {pcap_file}")
        sys.exit(1)

    print(f"Analyzing DNS traffic in {pcap_file}...")
    
    # The tshark command to filter for DNS queries and extract fields
    tshark_command = [
        'tshark', '-r', pcap_file,
        '-Y', 'dns.flags.response == 0', # Filter for DNS queries only
        '-T', 'fields',
        '-e', 'ip.src',
        '-e', 'dns.qry.name'
    ]

    try:
        result = subprocess.run(tshark_command, capture_output=True, text=True, check=True)
        dns_queries = result.stdout.strip().split('\n')
        
        if not dns_queries or dns_queries == ['']:
            print("No DNS queries found.")
            return

        print("--- DNS Analysis Results ---")
        query_sources = defaultdict(set)
        for line in dns_queries:
            if line:
                src_ip, query_name = line.split('\t')
                query_sources[query_name].add(src_ip)
        
        for query, sources in query_sources.items():
            print(f"Query: {query}")
            print(f"  Source IP(s): {', '.join(sources)}")
            print("-" * 20)
            
    except FileNotFoundError:
        print("Error: tshark command not found. Make sure Wireshark is installed and in your PATH.")
    except subprocess.CalledProcessError as e:
        print(f"Error running tshark: {e}")
        print(f"Tshark output:\n{e.stderr}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 dns_agent.py <pcap_file>")
        sys.exit(1)
    
    pcap_file_path = sys.argv[1]
    analyze_dns(pcap_file_path)
