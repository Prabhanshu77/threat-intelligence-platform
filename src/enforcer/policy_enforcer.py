import sys
import os
import subprocess
import logging
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from src.database.db_connector import get_high_risk_ips, ip_collection

# Setup logging
# This creates a log file that records everything the enforcer does
# Think of it like a security guard's notebook
logging.basicConfig(
    filename='logs/enforcer.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def block_ip(ip_address):
    """
    Block a single IP address using Linux iptables
    iptables is Linux's built in firewall
    This command tells the firewall to DROP all
    packets coming from this IP address
    """
    try:
        # This is the actual firewall command
        # -A INPUT means add rule for incoming traffic
        # -s means source IP address
        # -j DROP means drop/block all packets from this IP
        command = [
            "sudo", "iptables",
            "-A", "INPUT",
            "-s", ip_address,
            "-j", "DROP"
        ]

        # Run the command
        result = subprocess.run(
            command,
            capture_output=True,
            text=True
        )

        if result.returncode == 0:
            # Log the successful block
            logging.info(f"BLOCKED: {ip_address}")
            print(f"✅ Blocked IP: {ip_address}")

            # Update database to mark IP as blocked
            ip_collection.update_one(
                {"ip": ip_address},
                {"$set": {
                    "is_blocked": True,
                    "blocked_at": datetime.now()
                }}
            )
            return True
        else:
            logging.error(f"Failed to block {ip_address}: {result.stderr}")
            print(f"❌ Failed to block {ip_address}: {result.stderr}")
            return False

    except Exception as e:
        logging.error(f"Error blocking {ip_address}: {e}")
        print(f"❌ Error: {e}")
        return False

def unblock_ip(ip_address):
    """
    Unblock an IP address — this is the rollback mechanism
    Sometimes legitimate IPs get flagged as malicious
    This function reverses the block
    -D means Delete the rule instead of adding it
    """
    try:
        command = [
            "sudo", "iptables",
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
            logging.info(f"UNBLOCKED: {ip_address}")
            print(f"✅ Unblocked IP: {ip_address}")

            # Update database
            ip_collection.update_one(
                {"ip": ip_address},
                {"$set": {
                    "is_blocked": False,
                    "unblocked_at": datetime.now()
                }}
            )
            return True
        else:
            logging.error(f"Failed to unblock {ip_address}: {result.stderr}")
            print(f"❌ Failed to unblock: {result.stderr}")
            return False

    except Exception as e:
        logging.error(f"Error unblocking {ip_address}: {e}")
        print(f"❌ Error: {e}")
        return False

def show_blocked_ips():
    """
    Show all currently blocked IPs
    This reads the actual firewall rules
    """
    print("\n=== Currently Blocked IPs ===")
    result = subprocess.run(
        ["sudo", "iptables", "-L", "INPUT", "-n"],
        capture_output=True,
        text=True
    )
    print(result.stdout)

def run_enforcer():
    """
    Main enforcer function
    This reads all high risk IPs from database
    and blocks them automatically
    """
    print("=" * 50)
    print("DYNAMIC POLICY ENFORCER STARTING")
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 50)

    # Get all high risk IPs from database
    # min_score=7 means only block IPs with risk score 7 or above
    high_risk_ips = get_high_risk_ips(min_score=7)

    print(f"\nFound {len(high_risk_ips)} high risk IPs to block")
    print("-" * 30)

    blocked = 0
    already_blocked = 0
    failed = 0

    for ip_data in high_risk_ips:
        ip = ip_data["ip"]
        score = ip_data["risk_score"]
        country = ip_data.get("country", "Unknown")
        is_blocked = ip_data.get("is_blocked", False)

        # Skip if already blocked
        if is_blocked:
            already_blocked += 1
            continue

        print(f"\nBlocking: {ip} | Country: {country} | Risk Score: {score}")

        result = block_ip(ip)
        if result:
            blocked += 1
        else:
            failed += 1

    # Show summary
    print("\n" + "=" * 50)
    print("ENFORCER COMPLETE!")
    print(f"Newly blocked: {blocked}")
    print(f"Already blocked: {already_blocked}")
    print(f"Failed: {failed}")
    print("=" * 50)

    # Show current firewall rules
    show_blocked_ips()

if __name__ == "__main__":
    run_enforcer()
