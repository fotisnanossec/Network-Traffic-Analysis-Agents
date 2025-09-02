import requests
import os
import sys
import time
from dotenv import load_dotenv
from requests.exceptions import HTTPError, Timeout, RequestException

# Load environment variables from .env file
load_dotenv()

# Use a session for persistent connections (more efficient)
session = requests.Session()

def check_ip(ip):
    """
    Checks the reputation of an IP address using the AbuseIPDB API.
    """
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        print("Error: ABUSEIPDB_API_KEY not found in .env file.")
        return

    # Respect API rate limits by adding a delay
    print("Waiting 15 seconds to respect API rate limits...")
    time.sleep(15)

    url = 'https://api.abuseipdb.com/api/v2/check'
    headers = {'Accept': 'application/json', 'Key': api_key}
    params = {'ipAddress': ip, 'maxAgeInDays': '90'}

    try:
        response = session.get(url, headers=headers, params=params, timeout=30)
        response.raise_for_status()  # Raise an HTTPError for bad responses (4xx or 5xx)
        data = response.json().get('data')

        if data:
            print(f"\n--- AbuseIPDB Report for {ip} ---")
            print(f"Confidence Score: {data.get('abuseConfidenceScore')}%")
            print(f"Total Reports: {data.get('totalReports')}")
            print(f"Country: {data.get('countryName')}")
            print(f"ISP: {data.get('isp')}")
            print("-" * 30)
        else:
            print(f"No data found for IP: {ip}")

    except HTTPError as http_err:
        print(f"HTTP error occurred: {http_err} - Check your API key or the request format.")
    except Timeout as timeout_err:
        print(f"Timeout error occurred: {timeout_err} - The request took too long to complete.")
    except RequestException as req_err:
        print(f"An error occurred: {req_err}")


def check_domain(domain):
    """
    Checks the reputation of a domain using the VirusTotal API.
    """
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        print("Error: VIRUSTOTAL_API_KEY not found in .env file.")
        return

    # Respect API rate limits by adding a delay
    print("Waiting 15 seconds to respect API rate limits...")
    time.sleep(15)

    url = 'https://www.virustotal.com/api/v3/domains/' + domain
    headers = {'x-apikey': api_key}

    try:
        response = session.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        data = response.json().get('data')

        if data:
            attributes = data.get('attributes')
            if attributes:
                last_analysis_stats = attributes.get('last_analysis_stats', {})
                print(f"\n--- VirusTotal Report for {domain} ---")
                print(f"Harmless: {last_analysis_stats.get('harmless', 0)}")
                print(f"Malicious: {last_analysis_stats.get('malicious', 0)}")
                print(f"Suspicious: {last_analysis_stats.get('suspicious', 0)}")
                print(f"Undetected: {last_analysis_stats.get('undetected', 0)}")
                print("-" * 30)
            else:
                print(f"No analysis stats found for domain: {domain}")
        else:
            print(f"No data found for domain: {domain}")
            
    except HTTPError as http_err:
        print(f"HTTP error occurred: {http_err} - Check your API key or the request format.")
    except Timeout as timeout_err:
        print(f"Timeout error occurred: {timeout_err} - The request took too long to complete.")
    except RequestException as req_err:
        print(f"An error occurred: {req_err}")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 check_threats.py --ip <ip_address> or --domain <domain>")
        sys.exit(1)

    if sys.argv[1] == '--ip':
        check_ip(sys.argv[2])
    elif sys.argv[1] == '--domain':
        check_domain(sys.argv[2])
    else:
        print("Invalid argument. Use --ip or --domain.")
