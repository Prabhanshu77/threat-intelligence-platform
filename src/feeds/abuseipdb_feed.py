# This imports libraries we need
import requests
import os
from dotenv import load_dotenv

# This loads your API key from the .env file
load_dotenv()
API_KEY = os.getenv("ABUSEIPDB_API_KEY")

# This is the website address we are fetching data from
URL = "https://api.abuseipdb.com/api/v2/blacklist"

# These are the settings for our request
# limit=100 means fetch top 100 hacker IPs
headers = {
    "Key": API_KEY,
    "Accept": "application/json"
}

params = {
    "confidenceMinimum": 90,
    "limit": 100
}

def fetch_blacklist():
    print("Fetching hacker IPs from AbuseIPDB...")
    
    # This sends the request to AbuseIPDB
    response = requests.get(URL, headers=headers, params=params)
    
    # This checks if it worked
    if response.status_code == 200:
        data = response.json()
        ip_list = data["data"]
        
        print(f"Success! Found {len(ip_list)} malicious IPs")
        
        # This prints each IP we found
        for item in ip_list:
            print(f"IP: {item['ipAddress']} | Country: {item['countryCode']} | Abuse Score: {item['abuseConfidenceScore']}")
        
        return ip_list
    
    else:
        print(f"Error: {response.status_code}")
        return []

# This runs the function when we execute the script
if __name__ == "__main__":
    fetch_blacklist()
