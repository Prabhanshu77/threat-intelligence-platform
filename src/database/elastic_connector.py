import sys
import os
import traceback
from dotenv import load_dotenv
from elasticsearch import Elasticsearch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from src.database.db_connector import get_all_ips

load_dotenv()

es = Elasticsearch(
    "http://localhost:9200",
    verify_certs=False,
    ssl_show_warn=False
)

def create_index():
    index_name = "threat_intelligence"

    if es.indices.exists(index=index_name):
        print(f"Index '{index_name}' already exists")
        return

    es.indices.create(
        index=index_name,
        mappings={
            "properties": {
                "ip": {"type": "keyword"},
                "country": {"type": "keyword"},
                "risk_score": {"type": "float"},
                "abuse_score": {"type": "float"},
                "source": {"type": "keyword"},
                "is_blocked": {"type": "boolean"},
                "saved_at": {"type": "date"}
            }
        }
    )
    print(f"Index '{index_name}' created successfully!")

def fix_date(saved_at):
    """Convert date to Elasticsearch format"""
    if hasattr(saved_at, 'strftime'):
        return saved_at.strftime("%Y-%m-%dT%H:%M:%S")
    else:
        return str(saved_at).replace(" ", "T").split(".")[0]

def sync_mongodb_to_elastic():
    print("Syncing MongoDB data to Elasticsearch...")

    all_ips = get_all_ips()
    print(f"Found {len(all_ips)} IPs in MongoDB")

    synced = 0
    errors = 0

    for ip_data in all_ips:
        try:
            ip_data.pop("_id", None)

            if "saved_at" in ip_data:
                ip_data["saved_at"] = fix_date(ip_data["saved_at"])

            es.index(
                index="threat_intelligence",
                id=ip_data["ip"],
                document=ip_data
            )
            synced += 1

        except Exception as e:
            print(f"Error syncing {ip_data.get('ip', 'unknown')}: {e}")
            errors += 1

    print(f"Done! Synced: {synced} | Errors: {errors}")

if __name__ == "__main__":
    print("Testing Elasticsearch connection...")

    try:
        info = es.info()
        print(f"Connected successfully!")
        print(f"Elasticsearch version: {info['version']['number']}")
        create_index()
        sync_mongodb_to_elastic()
    except Exception as e:
        print(f"Connection failed: {e}")
        traceback.print_exc()
