import sys
import os
import logging
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from src.database.db_connector import ip_collection

# Setup logging for alerts
logging.basicConfig(
    filename='logs/alerts.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def send_alert(ip_data, alert_type="HIGH_RISK"):
    """
    Send an alert when a threat is detected
    In a real system this would send an email or SMS
    For our project it logs and prints the alert
    """
    ip = ip_data.get("ip", "Unknown")
    country = ip_data.get("country", "Unknown")
    risk_score = ip_data.get("risk_score", 0)
    source = ip_data.get("source", "Unknown")

    # Create alert message
    alert_message = (
        f"🚨 SECURITY ALERT 🚨\n"
        f"Type: {alert_type}\n"
        f"IP Address: {ip}\n"
        f"Country: {country}\n"
        f"Risk Score: {risk_score}/10\n"
        f"Source: {source}\n"
        f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"Action: IP has been automatically blocked"
    )

    # Print alert to screen
    print("\n" + "=" * 50)
    print(alert_message)
    print("=" * 50)

    # Save to log file
    logging.warning(f"ALERT - IP: {ip} | Country: {country} | Score: {risk_score} | Source: {source}")

    # Save alert to database
    ip_collection.update_one(
        {"ip": ip},
        {"$set": {
            "alert_sent": True,
            "alert_time": datetime.now(),
            "alert_type": alert_type
        }}
    )

def check_critical_threats():
    """
    Check for critical threats — risk score 9 or 10
    These are the most dangerous IPs
    """
    print("\n🔍 Checking for critical threats...")

    critical = list(ip_collection.find({
        "risk_score": {"$gte": 9},
        "is_blocked": True
    }))

    print(f"\n⚠️  Found {len(critical)} CRITICAL threats (score 9-10)")
    print("-" * 40)

    for ip_data in critical[:5]:
        print(f"IP: {ip_data['ip']} | "
              f"Country: {ip_data.get('country', 'Unknown')} | "
              f"Score: {ip_data['risk_score']} | "
              f"Source: {ip_data.get('source', 'Unknown')}")

    if len(critical) > 5:
        print(f"... and {len(critical) - 5} more critical threats")

    return critical

def generate_daily_summary():
    """
    Generate a daily summary report of all threats
    This is what a SOC analyst reads every morning
    """
    print("\n" + "=" * 50)
    print("📊 DAILY THREAT INTELLIGENCE SUMMARY")
    print(f"Date: {datetime.now().strftime('%Y-%m-%d')}")
    print("=" * 50)

    # Total IPs collected
    total = ip_collection.count_documents({})
    print(f"\n📌 Total IPs in database: {total}")

    # Total blocked
    blocked = ip_collection.count_documents({"is_blocked": True})
    print(f"🚫 Total IPs blocked: {blocked}")

    # High risk IPs
    high_risk = ip_collection.count_documents({"risk_score": {"$gte": 7}})
    print(f"⚠️  High risk IPs (score 7+): {high_risk}")

    # Critical IPs
    critical = ip_collection.count_documents({"risk_score": {"$gte": 9}})
    print(f"🔴 Critical IPs (score 9+): {critical}")

    # Breakdown by source
    print("\n📡 Threats by source:")
    for source in ["AbuseIPDB", "AlienVault OTX", "VirusTotal"]:
        count = ip_collection.count_documents({"source": source})
        print(f"  {source}: {count} IPs")

    # Breakdown by country top 5
    print("\n🌍 Top attacking countries:")
    pipeline = [
        {"$group": {"_id": "$country", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 5}
    ]
    countries = list(ip_collection.aggregate(pipeline))
    for country in countries:
        print(f"  {country['_id']}: {country['count']} IPs")

    print("\n" + "=" * 50)
    print("END OF DAILY SUMMARY")
    print("=" * 50)

    # Save summary to log
    logging.info(f"Daily summary - Total: {total} | Blocked: {blocked} | Critical: {critical}")

if __name__ == "__main__":
    print("Starting Alert System...")

    # Check for critical threats
    check_critical_threats()

    # Generate daily summary
    generate_daily_summary()
