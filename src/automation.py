import sys
import os
import schedule
import time
import logging
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from src.feeds.run_all_feeds import run_all_feeds
from src.database.elastic_connector import sync_mongodb_to_elastic, create_index
from src.enforcer.policy_enforcer import run_enforcer
from src.enforcer.alert_system import generate_daily_summary

# Setup logging
logging.basicConfig(
    filename='logs/automation.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def run_full_pipeline():
    """
    Main pipeline that runs every 6 hours automatically
    Collects threats, syncs data, blocks IPs, generates alerts
    """
    print("\n" + "=" * 60)
    print("🤖 AUTOMATED SECURITY PIPELINE STARTING")
    print(f"⏰ Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    logging.info("Automated pipeline started")

    # Step 1 — Collect threats
    print("\n📡 Step 1/4: Collecting threats from all feeds...")
    try:
        run_all_feeds()
        print("✅ Feeds completed!")
        logging.info("Feeds completed successfully")
    except Exception as e:
        print(f"❌ Feeds error: {e}")
        logging.error(f"Feeds error: {e}")

    # Step 2 — Sync to Elasticsearch
    print("\n🔄 Step 2/4: Syncing to Elasticsearch...")
    try:
        create_index()
        sync_mongodb_to_elastic()
        print("✅ Sync completed!")
        logging.info("Elasticsearch sync completed")
    except Exception as e:
        print(f"❌ Sync error: {e}")
        logging.error(f"Sync error: {e}")

    # Step 3 — Block new threats
    print("\n🚫 Step 3/4: Blocking new threats...")
    try:
        run_enforcer()
        print("✅ Blocking completed!")
        logging.info("Enforcer completed successfully")
    except Exception as e:
        print(f"❌ Enforcer error: {e}")
        logging.error(f"Enforcer error: {e}")

    # Step 4 — Generate alerts
    print("\n🔔 Step 4/4: Generating alert report...")
    try:
        generate_daily_summary()
        print("✅ Alerts generated!")
        logging.info("Alert system completed")
    except Exception as e:
        print(f"❌ Alert error: {e}")
        logging.error(f"Alert error: {e}")

    print("\n" + "=" * 60)
    print("✅ PIPELINE COMPLETE!")
    print(f"⏰ Next run in 6 hours")
    print(f"🕐 Time now: {datetime.now().strftime('%H:%M:%S')}")
    print("=" * 60)

    logging.info("Pipeline completed successfully")

def start_automation():
    """
    Start the 24/7 automation scheduler
    Runs pipeline every 6 hours to respect API limits
    """
    print("\n" + "=" * 60)
    print("🤖 THREAT INTELLIGENCE PLATFORM")
    print("🔒 24/7 AUTOMATED SECURITY SYSTEM")
    print("=" * 60)
    print("✅ System starting...")
    print("⏰ Pipeline runs every 6 hours automatically")
    print("📊 Daily summary runs every day at 8:00 AM")
    print("🛑 Press Ctrl+C to stop manually")
    print("=" * 60)

    logging.info("24/7 Automation system started")

    # Run immediately on startup
    # Don't wait 6 hours for first protection
    print("\n🚀 Running initial pipeline now...")
    run_full_pipeline()

    # Schedule every 6 hours
    # Respects free API rate limits
    schedule.every(6).hours.do(run_full_pipeline)

    # Daily summary at 8am
    # Like a morning briefing for SOC analyst
    schedule.every().day.at("08:00").do(generate_daily_summary)

    print("\n✅ Scheduler is now active!")
    print("📅 Full pipeline: Every 6 hours")
    print("📊 Daily summary: Every day at 8:00 AM")
    print("\n🔒 System is now protecting your network 24/7...")

    # Keep running forever
    # Checks every 30 seconds if a task needs to run
    while True:
        schedule.run_pending()
        time.sleep(30)

if __name__ == "__main__":
    start_automation()
