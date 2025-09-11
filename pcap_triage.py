import pyshark
import json
import os

def triage_pcap(pcap_file):
    if not os.path.exists(pcap_file):
        print(f"Error: PCAP file not found at {pcap_file}")
        return

    print(f"[*] Analyzing {pcap_file} for initial triage...")
    cap = pyshark.FileCapture(pcap_file)
    
    findings = {
        "top_ips": {},
        "unique_domains": {},
        "protocol_summary": {}
    }

    try:
        for packet in cap:
            # Get IP information
            if 'ip' in packet:
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
                findings["top_ips"][src_ip] = findings["top_ips"].get(src_ip, 0) + 1
                findings["top_ips"][dst_ip] = findings["top_ips"].get(dst_ip, 0) + 1

            # Get DNS information
            if 'dns' in packet:
                if hasattr(packet.dns, 'qry_name'):
                    domain = packet.dns.qry_name
                    findings["unique_domains"][domain] = findings["unique_domains"].get(domain, 0) + 1

            # Get protocol information
            for layer in packet.layers:
                layer_name = layer.layer_name
                findings["protocol_summary"][layer_name] = findings["protocol_summary"].get(layer_name, 0) + 1

    except Exception as e:
        print(f"Error during packet analysis: {e}")
    
    cap.close()

    # Sort findings for cleaner output
    findings["top_ips"] = {k: v for k, v in sorted(findings["top_ips"].items(), key=lambda item: item[1], reverse=True)}
    findings["unique_domains"] = {k: v for k, v in sorted(findings["unique_domains"].items(), key=lambda item: item[1], reverse=True)}
    
    output_path = "data/findings/triage_findings.json"
    with open(output_path, 'w') as f:
        json.dump(findings, f, indent=4)
        
    print(f"[*] Analysis complete. Findings saved to {output_path}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python3 pcap_triage.py <pcap_file>")
        sys.exit(1)
    
    triage_pcap(sys.argv[1])
