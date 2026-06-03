# Threat Intelligence Platform (TIP)

Advanced Threat Intelligence Platform for Financial Security

## Infotact Technical Internship Program
### Project 1: Finance & Banking Security

---

## What is this project?

An advanced Threat Intelligence Platform that automatically collects malicious IP addresses from multiple sources, stores them in a database, visualizes them on a dashboard, and automatically blocks them using Linux firewall.

---

## System Architecture
OSINT Feeds → Python Aggregator → MongoDB → Elasticsearch → Kibana Dashboard
↓
Dynamic Policy Enforcer
↓
Linux iptables Firewall
↓
Alert System + Rollback

---

## Features

- 3 OSINT threat feeds connected
- Automatic deduplication of threat data
- Risk scoring system (1-10 scale)
- Real time Kibana dashboard
- Automatic IP blocking via iptables
- Rollback mechanism for false positives
- Alert system with daily summary
- Complete audit logs

---

## Technology Stack

| Component | Technology |
|-----------|-----------|
| Feed Scripts | Python 3.13 |
| Database | MongoDB |
| Search Engine | Elasticsearch 8.x |
| Dashboard | Kibana |
| Firewall | Linux iptables |
| Version Control | Git + GitHub |

---

## Project Structure

threat-intelligence-platform/
├── src/
│   ├── feeds/
│   │   ├── abuseipdb_feed.py
│   │   ├── alienvault_feed.py
│   │   ├── virustotal_feed.py
│   │   └── run_all_feeds.py
│   ├── database/
│   │   ├── db_connector.py
│   │   └── elastic_connector.py
│   ├── enforcer/
│   │   ├── policy_enforcer.py
│   │   ├── rollback.py
│   │   └── alert_system.py
│   └── dashboard/
├── logs/
├── tests/
├── .env (not in GitHub - contains API keys)
├── .gitignore
└── requirements.txt

---

## How to run

### Step 1 - Start services
```bash
sudo systemctl start mongodb
sudo systemctl start elasticsearch
sudo systemctl start kibana
```

### Step 2 - Activate Python environment
```bash
source venv/bin/activate
```

### Step 3 - Run all feeds
```bash
python3 -m src.feeds.run_all_feeds
```

### Step 4 - Sync to Elasticsearch
```bash
python3 -m src.database.elastic_connector
```

### Step 5 - Run enforcer
```bash
python3 -m src.enforcer.policy_enforcer
```

### Step 6 - Check alerts
```bash
python3 -m src.enforcer.alert_system
```

### Step 7 - Rollback if needed
```bash
python3 -m src.enforcer.rollback
```

### Step 8 - View dashboard
Open browser and go to http://localhost:5601

---

## Results

- 231 real malicious IPs collected
- 222 IPs automatically blocked
- 3 threat intelligence sources connected
- Real time dashboard with 2 visualizations
- Complete audit trail in logs/

---

## Security Practices

- API keys stored in .env file
- .env never pushed to GitHub
- Feature branches used throughout
- Daily commits maintained
- Meaningful commit messages used

---

## Developer

- Name: Prabhanshu
- GitHub: Prabhanshu77
- Internship: Infotact Technical Program
- Project: Finance & Banking Cybersecurity

- Project 1 complete - 396 IPs collected, 385 blocked automatically
