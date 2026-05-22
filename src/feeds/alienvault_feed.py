import requests
import os
from dotenv import load_dotenv
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from src.database.db_connector import save_ip, count_ips

load_dotenv()
API_KEY = os.getenv("ALIENVAULT_API_KEY")

# This endpoint gives us malicious IPs from recent threat pulses
BASE_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"

headers = {
    "X-OTX-API-KEY": API_KEY
}

def fetch_and_save_alienvault():
    print("Fetching threat pulses from AlienVault OTX...")

    saved = 0
    skipped = 0

    # Fetch first 5 pages of threat pulses
    for page in range(1, 6):
        print(f"Fetching page {page}...")
        
        response = requests.get(
            BASE_URL,
            headers=headers,
            params={"page": page, "limit": 10}
        )

        if response.status_code != 200:
            print(f"Error on page {page}: {response.status_code}")
            break

        data = response.json()
        pulses = data.get("results", [])

        if not pulses:
            print("No more pulses found")
            break

        # Each pulse contains multiple indicators
        for pulse in pulses:
            indicators = pulse.get("indicators", [])

            for indicator in indicators:
                # Only save IPv4 addresses
                if indicator.get("type") != "IPv4":
                    continue

                ip = indicator.get("indicator", "").strip()
                if not ip:
                    continue

                ip_data = {
                    "ip": ip,
                    "country": "Unknown",
                    "abuse_score": 80,
                    "risk_score": 8.0,
                    "source": "AlienVault OTX",
                    "pulse_name": pulse.get("name", "Unknown"),
                    "is_blocked": False
                }

                result = save_ip(ip_data)
                if result:
                    saved += 1
                else:
                    skipped += 1

    print(f"Done! Saved: {saved} new IPs | Skipped: {skipped} duplicates")
    print(f"Total IPs in database: {count_ips()}")

if __name__ == "__main__":
    fetch_and_save_alienvault()
