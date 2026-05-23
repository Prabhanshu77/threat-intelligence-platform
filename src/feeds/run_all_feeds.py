# This is the main commander script
# It runs all 3 feeds one by one automatically
import sys
import os
from datetime import datetime

# This helps Python find our project files
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

# Import all 3 feed functions
from src.feeds.abuseipdb_feed import fetch_and_save_blacklist
from src.feeds.alienvault_feed import fetch_and_save_alienvault
from src.feeds.virustotal_feed import fetch_and_save_virustotal
from src.database.db_connector import count_ips

def run_all_feeds():
    """
    This function runs all 3 feeds one by one
    and shows a summary at the end
    """
    
    # Show start time
    start_time = datetime.now()
    print("=" * 50)
    print("THREAT INTELLIGENCE PLATFORM")
    print("Starting all feeds...")
    print(f"Time: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 50)

    # Count IPs before running
    ips_before = count_ips()

    # Run feed 1 — AbuseIPDB
    print("\n[1/3] Running AbuseIPDB feed...")
    print("-" * 30)
    try:
        fetch_and_save_blacklist()
        print("AbuseIPDB feed completed successfully!")
    except Exception as e:
        print(f"AbuseIPDB feed failed: {e}")

    # Run feed 2 — AlienVault
    print("\n[2/3] Running AlienVault OTX feed...")
    print("-" * 30)
    try:
        fetch_and_save_alienvault()
        print("AlienVault feed completed successfully!")
    except Exception as e:
        print(f"AlienVault feed failed: {e}")

    # Run feed 3 — VirusTotal
    print("\n[3/3] Running VirusTotal feed...")
    print("-" * 30)
    try:
        fetch_and_save_virustotal()
        print("VirusTotal feed completed successfully!")
    except Exception as e:
        print(f"VirusTotal feed failed: {e}")

    # Show final summary
    ips_after = count_ips()
    new_ips = ips_after - ips_before
    end_time = datetime.now()
    duration = (end_time - start_time).seconds

    print("\n" + "=" * 50)
    print("ALL FEEDS COMPLETED!")
    print(f"New IPs added: {new_ips}")
    print(f"Total IPs in database: {ips_after}")
    print(f"Time taken: {duration} seconds")
    print("=" * 50)

if __name__ == "__main__":
    run_all_feeds()
