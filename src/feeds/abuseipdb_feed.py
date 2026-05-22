# This imports libraries we need
import requests
import os
from dotenv import load_dotenv
import sys

# This adds the project root to Python path
# So we can import our database connector
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from src.database.db_connector import save_ip, count_ips

# This loads your API key from the .env file
load_dotenv()
API_KEY = os.getenv("ABUSEIPDB_API_KEY")

# This is the website address we are fetching data from
URL = "https://api.abuseipdb.com/api/v2/blacklist"

# These are the settings for our request
headers = {
    "Key": API_KEY,
    "Accept": "application/json"
}

params = {
    "confidenceMinimum": 90,
    "limit": 100
}

def calculate_risk_score(abuse_score):
    """
    Convert AbuseIPDB score (0-100) to our risk score (1-10)
    This makes all our feeds use the same scoring system
    """
    return round((abuse_score / 100) * 10, 1)

def fetch_and_save_blacklist():
    print("Fetching hacker IPs from AbuseIPDB...")
    
    # This sends the request to AbuseIPDB
    response = requests.get(URL, headers=headers, params=params)
    
    # This checks if it worked
    if response.status_code == 200:
        data = response.json()
        ip_list = data["data"]
        
        print(f"Found {len(ip_list)} malicious IPs")
        
        # Track how many we saved
        saved = 0
        skipped = 0
        
        # Save each IP to MongoDB
        for item in ip_list:
            
            # Build the data structure we want to save
            ip_data = {
                "ip": item["ipAddress"],
                "country": item["countryCode"],
                "abuse_score": item["abuseConfidenceScore"],
                "risk_score": calculate_risk_score(item["abuseConfidenceScore"]),
                "source": "AbuseIPDB",
                "is_blocked": False
            }
            
            # Save to MongoDB
            result = save_ip(ip_data)
            if result:
                saved += 1
            else:
                skipped += 1
        
        print(f"Done! Saved: {saved} new IPs | Skipped: {skipped} duplicates")
        print(f"Total IPs in database: {count_ips()}")
        
        return ip_list
    
    else:
        print(f"Error: {response.status_code}")
        return []

# This runs the function when we execute the script
if __name__ == "__main__":
    fetch_and_save_blacklist()
