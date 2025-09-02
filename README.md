### 🛡️ Network Traffic Analysis Agents

This project contains a collection of Python scripts designed for a modular approach to network traffic analysis. Each script serves as a specialized "agent" to perform a specific type of analysis on a PCAP (Packet Capture) file, automating routine tasks for cybersecurity professionals.

### 🌟 Features

  * **PCAP Triage (`pcap_triage.py`):** Quickly analyzes a PCAP file to generate an initial report containing top IPs, unique domains, and a protocol summary.
  * **DNS Agent (`dns_agent.py`):** Extracts and analyzes all DNS queries from a PCAP to identify potential suspicious domain lookups.
  * **HTTP Agent (`http_agent.py`):** Analyzes HTTP traffic to report on hosts, full URIs, and user agents.
  * **Scanning Agent (`scanning_agent.py`):** Detects potential network scanning activity by identifying high volumes of TCP SYN or FIN packets to multiple ports or IPs.
  * **Threat Intelligence (`check_threats.py`):** Checks IPs and domains against external threat intelligence databases like AbuseIPDB and VirusTotal.
  * **Stream Extraction (`get_stream.py`):** Extracts and saves the raw payload from a specific TCP stream for deeper analysis.

### ⚙️ Prerequisites

  * **Python 3.x:** Ensure you have Python installed on your system.

  * **`tshark`:** This tool is required for some of the scripts. It comes with Wireshark. Make sure it's installed and added to your system's PATH.

  * **Python Libraries:** You will need to install the following libraries:

      * `pyshark`
      * `requests`
      * `python-dotenv`

    You can install them by running:

    ```sh
    pip install pyshark requests python-dotenv
    ```

  * **API Keys:** Some agents, like `check_threats.py`, require API keys from services like AbuseIPDB and VirusTotal. Create a `.env` file in the project's root directory and add your keys there:

    ```
    ABUSEIPDB_API_KEY="your_api_key_here"
    VIRUSTOTAL_API_KEY="your_api_key_here"
    ```

### ▶️ Usage

Each agent is a standalone script that can be run from the command line.

  * **Triage:** `python3 pcap_triage.py <pcap_file>`
  * **DNS Analysis:** `python3 dns_agent.py <pcap_file>`
  * **HTTP Analysis:** `python3 http_agent.py <pcap_file>`
  * **Scanning Analysis:** `python3 scanning_agent.py <pcap_file>`
  * **Threat Check:** `python3 check_threats.py --ip <ip_address>` or `--domain <domain>`
  * **Stream Extraction:** `python3 get_stream.py <pcap_file> <src_ip> <dst_ip> <dst_port>`

