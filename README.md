<<<<<<< HEAD
# 🛡️ AI-Based Cybersecurity Threat Detection

An end-to-end, machine learning-driven network security pipeline that ingests live data feeds, flags anomalies, and initiates automated defense actions.

## 🎯 Problem Statement

Modern computer networks generate massive volumes of data — millions of alerts every day. Traditional security tools use fixed rules and miss new or evolving cyber attacks. This project builds an automated system that finds and stops cyber threats in real-time using machine learning.

## 🏗️ Architecture

```
[Live Network Traffic] → [Data Preprocessing] → [AI Inference Engine] → [Automated Response]
       ↓                        ↓                       ↓                      ↓
  Logs & Packets          Feature Extraction       Anomaly Scoring        Block IP / Alert
```

## 🚀 Features

- **Automated Detection**: Spot attacks instantly without waiting for human review
- **Anomaly Scoring**: Flags activities that deviate from established baseline behavior using Isolation Forest
- **Threat Classification**: Categorizes threats into DoS, Probe, R2L, U2R, and Normal
- **Threat Sandbox & Packet Inspector**: Interactive scenario testing with 1-click presets and custom packet feature evaluation
- **Real-Time SecOps Dashboard**: Telemetry console with live streaming feed, analytics, and automated defense actions
- **Automated Mitigation & Firewall Export**: Triggers immediate IP blocks and generates ready-to-run `iptables`, `UFW`, and `pf.conf` rules
- **Incident Audit Export**: Download comprehensive security incident reports in CSV or JSON

## 📊 Dataset

Uses the **NSL-KDD** dataset — the gold standard benchmark for network intrusion detection:
- 41 features per network connection
- 5 classes: Normal, DoS, Probe, R2L, U2R
- 125,973 training records / 22,544 test records

## 🛠️ Tech Stack

| Component | Technology |
|-----------|-----------|
| Language | Python 3.10+ |
| ML Frameworks | Scikit-learn, TensorFlow/Keras |
| Data Processing | Pandas, NumPy |
| API | Flask |
| Dashboard | HTML5, CSS3, JavaScript |
| Charts | Chart.js |

## 📦 Installation

```bash
# Clone the repository
git clone <repository-url>
cd "Ai Based CyberSecurity Threat Detection"

# Install dependencies
pip install -r requirements.txt
```

## 🏃 Quick Start

### Run Complete Pipeline, Verify, or Launch API
```bash
# Run full end-to-end pipeline (Data Ingestion, Training, Verification, API)
./venv/bin/python run_pipeline.py

# Or launch API server & dashboard only:
./venv/bin/python run_pipeline.py --api

# Or run the automated verification & debug test suite:
./venv/bin/python run_pipeline.py --verify
```
Then open **http://localhost:5050** in your browser.

## 📈 Performance Targets

| Metric | Target |
|--------|--------|
| Detection Accuracy | ≥ 98% |
| False Positive Rate | ≤ 0.1% |
| Detection Latency | < 500ms |
| Threat Classification F1 | ≥ 95% |

## 📄 License

This project is developed for cybersecurity research and network defense automation.
=======
# CyberSecurity_threat_detection
>>>>>>> 6fc7b569f3d61f3f5ede7e16067877ddcc7d4d5a
