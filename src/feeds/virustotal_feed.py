# Import libraries we need
import requests
import os
from dotenv import load_dotenv
import sys

# This helps Python find our other project files
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from src.database.db_connector import save_ip, count_ips

# Load API key from .env file
load_dotenv()
API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

# VirusTotal API address
# This fetches IPs that multiple engines flagged as malicious
BASE_URL = "https://www.virustotal.com/api/v3/ip_addresses"

# These headers tell VirusTotal who we are
headers = {
    "x-apikey": API_KEY
}

# List of known malicious IPs to check
# Free VirusTotal API checks one IP at a time
# So we check a list of commonly reported ones
SAMPLE_IPS = [
    "185.220.101.1",
    "185.220.101.2",
    "185.220.101.3",
    "192.42.116.1",
    "192.42.116.2",
    "89.234.157.254",
    "171.25.193.77",
    "171.25.193.78",
    "199.87.154.255",
    "64.113.32.29"
]

def calculate_risk_score(malicious_count, total_engines):
    """
    Calculate risk score based on how many
    antivirus engines flagged this IP
    More engines flagging = higher risk score
    """
    if total_engines == 0:
        return 0
    ratio = malicious_count / total_engines
    return round(ratio * 10, 1)

def fetch_and_save_virustotal():
    print("Fetching threat data from VirusTotal...")

    saved = 0
    skipped = 0
    errors = 0

    # Check each IP one by one
    for ip in SAMPLE_IPS:
        print(f"Checking IP: {ip}")

        # Send request to VirusTotal
        response = requests.get(
            f"{BASE_URL}/{ip}",
            headers=headers
        )

        # Check if request worked
        if response.status_code == 200:
            data = response.json()

            # Get analysis statistics
            stats = data["data"]["attributes"]["last_analysis_stats"]
            malicious = stats.get("malicious", 0)
            total = sum(stats.values())
            country = data["data"]["attributes"].get("country", "Unknown")

            # Only save if at least 1 engine flagged it
            if malicious > 0:
                ip_data = {
                    "ip": ip,
                    "country": country,
                    "abuse_score": round((malicious/total) * 100),
                    "risk_score": calculate_risk_score(malicious, total),
                    "malicious_engines": malicious,
                    "total_engines": total,
                    "source": "VirusTotal",
                    "is_blocked": False
                }

                result = save_ip(ip_data)
                if result:
                    saved += 1
                    print(f"Saved! {malicious}/{total} engines flagged this IP")
                else:
                    skipped += 1

        elif response.status_code == 429:
            # 429 means too many requests
            print("Rate limit reached - VirusTotal allows 4 requests per minute on free plan")
            break

        else:
            print(f"Error checking {ip}: {response.status_code}")
            errors += 1

    print(f"\nDone! Saved: {saved} | Skipped: {skipped} | Errors: {errors}")
    print(f"Total IPs in database: {count_ips()}")

if __name__ == "__main__":
    fetch_and_save_virustotal()
