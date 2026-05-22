from pymongo import MongoClient
from datetime import datetime

# Connect to MongoDB
client = MongoClient("mongodb://localhost:27017/")

# Create database
db = client["threat_intelligence"]

# Create collection (like a table)
ip_collection = db["malicious_ips"]

def save_ip(ip_data):
    """Save a single malicious IP to database"""
    
    # Check if IP already exists
    existing = ip_collection.find_one({"ip": ip_data["ip"]})
    
    if existing:
        print(f"IP {ip_data['ip']} already exists - skipping")
        return False
    
    # Add timestamp
    ip_data["saved_at"] = datetime.now()
    
    # Save to MongoDB
    ip_collection.insert_one(ip_data)
    print(f"Saved new IP: {ip_data['ip']}")
    return True

def get_high_risk_ips(min_score=7):
    """Get all IPs with risk score 7 or above"""
    results = ip_collection.find({"risk_score": {"$gte": min_score}})
    return list(results)

def get_all_ips():
    """Get all IPs from database"""
    return list(ip_collection.find())

def count_ips():
    """Count total IPs in database"""
    return ip_collection.count_documents({})

if __name__ == "__main__":
    print("Testing database connection...")
    print(f"Connected to: {db.name}")
    print(f"Total IPs: {count_ips()}")
