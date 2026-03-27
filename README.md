# MiniIDS

# 🛡️ MiniIDS IDS

<img width="754" height="554" alt="image" src="https://github.com/user-attachments/assets/516e2582-1526-4866-a6de-0511a5843844" />

A lightweight Intrusion Detection System (IDS) built with Python that monitors network traffic in real time and detects suspicious activities such as SYN floods, port scans, and abnormal connection spikes.

---

## 🚀 Features

* 📡 Real-time packet sniffing using Scapy
* ⚠️ Detects:

  * SYN Flood attacks
  * Port scanning behavior
  * High traffic anomalies
* 🖥️ User-friendly GUI built with Tkinter
* 🔌 Network interface selection
* 📝 Automatic logging of alerts
* 🔄 Live alert feed in the application

---

## 🧠 How It Works

MiniIDS monitors incoming packets and tracks behavior per IP address within a time window:

* **SYN Flood Detection**
  Flags excessive SYN packets from a single source

* **Port Scan Detection**
  Detects multiple ports being targeted by the same IP

* **Traffic Spike Detection**
  Identifies unusually high connection counts

Example:
If a device sends SYN packets to 20+ ports in a few seconds → 🚨 Alert triggered

---

## 📸 Interface Overview

* Start/Stop IDS engine
* Select network interface
* View real-time alerts
* Refresh available interfaces

---

## 🛠️ Installation

### 1. Clone the repository

```bash
git clone https://github.com/yourusername/MiniIDS-ids.git
cd MiniIDS-ids
```

### 2. Install dependencies

```bash
pip install scapy
```

### 3. Run the program

```bash
python main.py
```

---

## ⚠️ Requirements

* Python 3.x
* Administrative/root privileges (required for packet capture)

### Windows Users:

* Install **Npcap**
* Run terminal as Administrator

---

## 🧪 Testing Tip

* Use **Npcap Loopback Adapter** for localhost testing
* Use **Wi-Fi/Ethernet** for real network monitoring
* Simulate:

  * Port scans (e.g. nmap)
  * SYN flood tools (for educational purposes only)

---

## ⚙️ Configuration

You can tweak detection thresholds in the code:

```python
self.TIME_WINDOW = 5
self.SYN_THRESHOLD = 20
self.PORT_THRESHOLD = 15
self.CONN_THRESHOLD = 100
```

---

## 🔒 Disclaimer

This project is for **educational and defensive purposes only**.
Do not use it for unauthorized network monitoring.

