import subprocess
import os

def get_stream(pcap_file, src_ip, dst_ip, dst_port):
    if not os.path.exists(pcap_file):
        print(f"Error: PCAP file not found at {pcap_file}")
        return

    print(f"[*] Searching for stream between {src_ip} and {dst_ip}:{dst_port}...")

    # Step 1: Find the TCP stream index
    # Note: Using tshark's conv,tcp with a filter is the most reliable way to get the stream index
    command = [
        "tshark", "-r", pcap_file, "-q", "-z", "conv,tcp",
        f"ip.addr == {src_ip} and ip.addr == {dst_ip} and tcp.port == {dst_port}"
    ]
    
    try:
        proc = subprocess.run(command, capture_output=True, text=True, check=True)
        output_lines = proc.stdout.splitlines()

        # Find the line with the conversation and extract the stream number
        stream_index = None
        for line in output_lines:
            if src_ip in line or dst_ip in line:
                parts = line.split()
                if len(parts) > 1 and parts[0].isdigit():
                    stream_index = parts[0]
                    break
        
        if stream_index is None:
            print(f"No stream found for the specified IPs/port.")
            return

        print(f"[*] Found stream index: {stream_index}. Extracting payload...")

        # Step 2: Extract the stream payload
        # This command reconstructs the stream and outputs the raw data
        stream_command = [
            "tshark", "-r", pcap_file, "-q",
            "-z", f"follow,tcp,raw,{stream_index}"
        ]
        
        stream_proc = subprocess.run(stream_command, capture_output=True, text=True, check=True)
        stream_output = stream_proc.stdout
        
        output_path = f"data/findings/stream_{stream_index}.txt"
        with open(output_path, 'w') as f:
            f.write(stream_output)
            
        print(f"[*] TCP stream payload saved to {output_path}")

    except subprocess.CalledProcessError as e:
        print(f"Error running tshark: {e.stderr}")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 5:
        print("Usage: python3 get_stream.py <pcap_file> <src_ip> <dst_ip> <dst_port>")
        sys.exit(1)
    
    get_stream(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
