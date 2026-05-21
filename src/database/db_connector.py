# This imports the MongoDB library
from pymongo import MongoClient
import os
from dotenv import load_dotenv
from datetime import datetime

# Load environment variables
load_dotenv()

# This connects to MongoDB running on your computer
# 27017 is the default MongoDB port (like a door number)
client = MongoClient("mongodb://localhost:27017/")

# This creates a database called "threat_intelligence"
# Think of it like creating a new Excel workbook
db = client["threat_intelligence"]

# This creates a collection called "malicious_ips"
# Think of it like a sheet inside that workbook
ip_collection = db["malicious_ips"]

def save_ip(ip_data):
    """Save a single malicious IP to database"""
    
    # Check if this IP already exists in database
    # This prevents saving duplicate IPs
    existing = ip_collection.find_one({"ip": ip_data["ip"]})
    
    if existing:
        print(f"IP {ip_data['ip']} already exists - skipping")
        return False
    
    # Add timestamp of when we saved it
    ip_data["saved_at"] = datetime.now()
    
    # Save it to MongoDB
    ip_collection.insert_one(ip_data)
    print(f"Saved new IP: {ip_data['ip']}")
    return True

def get_high_risk_ips(min_score=7):
    """Get all IPs with risk score above minimum"""
    
    # This fetches only dangerous IPs from database
    # min_score=7 means only IPs with score 7 or above
    results = ip_collection.find({"risk_score": {"$gte": min_score}})
    return list(results)

def get_all_ips():
    """Get all IPs from database"""
    return list(ip_collection.find())

def count_ips():
    """Count how many IPs we have saved"""
    return ip_collection.count_documents({})

if __name__ == "__main__":
    print("Testing database connection...")
    print(f"Connected to database: {db.name}")
    print(f"Total IPs in database: {count_ips()}")
