# Threat Intelligence Platform (TIP)

Advanced Threat Intelligence Platform for Financial Security

## Infotact Technical Internship Program
### Project 1: Finance & Banking Security

---
#### Developer: Prabhanshu (GitHub: Prabhanshu77)
---
## What is this project?

An advanced Threat Intelligence Platform that automatically 
collects malicious IP addresses from multiple sources, stores 
them in a database, visualizes them on a dashboard, and 
automatically blocks them using Linux firewall - 24/7 without 
any human intervention.

---

## System Architecture

OSINT Feeds (3 sources)
↓
Python Aggregator (run_all_feeds.py)
↓
MongoDB Database (db_connector.py)
↓
Elasticsearch (elastic_connector.py)
↓
Kibana Dashboard (localhost:5601)
↓
Dynamic Policy Enforcer (policy_enforcer.py)
↓
Linux iptables Firewall (auto blocking)
↓
Alert System + Rollback Mechanism
↓
24/7 Systemd Service (threat-intelligence.service)

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
- 24/7 automated pipeline via systemd service
- Runs every 6 hours automatically
- Starts automatically on system boot
- Zero human intervention needed

---

## Technology Stack

| Component | Technology |
|-----------|-----------|
| Feed Scripts | Python 3.13 |
| Database | MongoDB |
| Search Engine | Elasticsearch 8.x |
| Dashboard | Kibana |
| Firewall | Linux iptables |
| Automation | Python schedule + systemd |
| Version Control | Git + GitHub |

---

## Project Structure

threat-intelligence-platform/
├── src/
│   ├── automation.py
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
│   ├── enforcer.log
│   ├── rollback.log
│   ├── alerts.log
│   └── automation.log
├── tests/
├── .env
├── .gitignore
└── requirements.txt
---

## How to run manually

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

### Step 3 - Run all feeds manually
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

## 24/7 Automatic Mode

### Start automation service
```bash
sudo systemctl start threat-intelligence
```

### Check service status
```bash
sudo systemctl status threat-intelligence
```

### View live logs
```bash
sudo journalctl -fu threat-intelligence
```

### Stop service
```bash
sudo systemctl stop threat-intelligence
```

---

## Final Results

- 396 real malicious IPs collected
- 385 IPs automatically blocked
- 296 critical threats detected
- 3 threat intelligence sources
- 2 Kibana visualizations
- 4 log files maintained
- 24/7 automated protection active

---

## Security Practices

- API keys stored in .env file
- .env never pushed to GitHub
- Feature branches used throughout
- Daily commits maintained
- Meaningful commit messages used
- Service runs as root for iptables access
- All actions logged with timestamps

---

## OSINT Sources

- AbuseIPDB - Community reported malicious IPs
- AlienVault OTX - Global threat intelligence
- VirusTotal - Multi engine IP analysis

---

## Git Branches

- main - Final clean code
- feature/osint-feeds - Feed scripts
- feature/database - Database connector
- feature/enforcer - Enforcer and automation

---

## Developer

- Name: Prabhanshu
- GitHub: Prabhanshu77
- Internship: Infotact Technical Program
- Project: Finance & Banking Cybersecurity
- Project 1 complete - 396 IPs collected, 385 blocked automatically
