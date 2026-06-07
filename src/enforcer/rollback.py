import sys
import os
import subprocess
import logging
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from src.database.db_connector import ip_collection

logging.basicConfig(
    filename='logs/rollback.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def block_ip_manually(ip_address):
    """
    Manually block a specific IP address
    """
    try:
        command = [
            "/sbin/iptables",
            "-A", "INPUT",
            "-s", ip_address,
            "-j", "DROP"
        ]

        result = subprocess.run(
            command,
            capture_output=True,
            text=True
        )

        if result.returncode == 0:
            logging.info(f"MANUAL BLOCK: {ip_address}")
            print(f"✅ Successfully blocked: {ip_address}")

            ip_collection.update_one(
                {"ip": ip_address},
                {"$set": {
                    "is_blocked": True,
                    "blocked_at": datetime.now(),
                    "block_reason": "Manual block by analyst"
                }}
            )
            return True
        else:
            print(f"❌ Failed to block {ip_address}")
            print(f"Reason: {result.stderr}")
            return False

    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def unblock_ip(ip_address):
    """
    Unblock a single IP address
    """
    try:
        command = [
            "/sbin/iptables",
            "-D", "INPUT",
            "-s", ip_address,
            "-j", "DROP"
        ]

        result = subprocess.run(
            command,
            capture_output=True,
            text=True
        )

        if result.returncode == 0:
            logging.info(f"ROLLBACK SUCCESS: {ip_address}")
            print(f"✅ Successfully unblocked: {ip_address}")

            ip_collection.update_one(
                {"ip": ip_address},
                {"$set": {
                    "is_blocked": False,
                    "unblocked_at": datetime.now(),
                    "unblock_reason": "Manual rollback by analyst"
                }}
            )
            return True
        else:
            print(f"❌ Failed to unblock {ip_address}")
            print(f"Reason: {result.stderr}")
            return False

    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def unblock_all():
    """
    Emergency unblock all IPs
    """
    print("⚠️  EMERGENCY UNBLOCK ALL STARTED")

    result = subprocess.run(
        ["/sbin/iptables", "-F", "INPUT"],
        capture_output=True,
        text=True
    )

    if result.returncode == 0:
        ip_collection.update_many(
            {"is_blocked": True},
            {"$set": {
                "is_blocked": False,
                "unblocked_at": datetime.now(),
                "unblock_reason": "Emergency unblock all"
            }}
        )
        logging.warning("EMERGENCY UNBLOCK ALL EXECUTED")
        print("✅ All IPs unblocked successfully!")
    else:
        print(f"❌ Failed: {result.stderr}")

def show_blocked_ips():
    """
    Show all blocked IPs from database
    """
    blocked = list(ip_collection.find({"is_blocked": True}))

    print("\n=== Currently Blocked IPs ===")
    print(f"Total blocked: {len(blocked)}")
    print("-" * 40)

    for ip_data in blocked[:10]:
        print(f"IP: {ip_data['ip']} | "
              f"Country: {ip_data.get('country', 'Unknown')} | "
              f"Risk Score: {ip_data.get('risk_score', 0)} | "
              f"Source: {ip_data.get('source', 'Unknown')}")

    if len(blocked) > 10:
        print(f"... and {len(blocked) - 10} more")

def show_menu():
    print("\n" + "=" * 50)
    print("THREAT INTELLIGENCE ROLLBACK SYSTEM")
    print("=" * 50)
    print("1. Show all blocked IPs")
    print("2. Unblock a specific IP")
    print("3. Manually block an IP")
    print("4. Emergency unblock all")
    print("5. Exit")
    print("=" * 50)

if __name__ == "__main__":
    while True:
        show_menu()
        choice = input("\nEnter your choice (1-5): ")

        if choice == "1":
            show_blocked_ips()

        elif choice == "2":
            ip = input("Enter IP address to unblock: ")
            unblock_ip(ip)

        elif choice == "3":
            ip = input("Enter IP address to block: ")
            block_ip_manually(ip)

        elif choice == "4":
            confirm = input("Are you sure? Type YES to confirm: ")
            if confirm == "YES":
                unblock_all()
            else:
                print("Cancelled!")

        elif choice == "5":
            print("Exiting rollback system...")
            break

        else:
            print("Invalid choice! Please enter 1-5")
