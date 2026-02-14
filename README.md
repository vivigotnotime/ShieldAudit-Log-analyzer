# 🔒 ShieldAudit: Secure Distributed Log Integrity Guard

**ShieldAudit** is a comprehensive security monitoring tool providing real-time log integrity verification, a distributed client-server architecture, and advanced analysis capabilities. It is designed to detect unauthorized modifications to log files and maintain immutable audit trails across distributed systems.
---

## 📋 Table of Contents
- [Features](#-features)
- [Architecture](#-architecture)
- [Installation](#-installation)
- [Usage Guide](#-usage-guide)
- [User Roles](#-user-roles)
- [Log Files](#-log-files)
- [Testing](#-testing)
- [Technical Details](#-technical-details)
- [License](#-license)

---

## ✨ Features

### 🔐 Security & Monitoring
* **Real-Time Integrity Monitoring:** Continuous SHA-256 hashing of log files.
* **Tamper Detection:** Instant alerts triggered when unauthorized modifications occur.
* **Encrypted Storage:** Credential protection using **PBKDF2HMAC** + **Fernet** encryption.
* **Role-Based Access Control (RBAC):** Three distinct user tiers with specific permissions.

### 📊 Log Management
* **Custom Data Structure:** High-performance circular buffer using a doubly linked list.
* **Categorized Logs:** Separate tracking for System, Security, Application, and Network logs.
* **Live Search:** Keyword searching with UI result highlighting and counters.

### 🌐 Network & GUI
* **Heartbeat Protocol:** Automated integrity checks every 5 seconds via TCP Sockets.
* **Multi-Client Support:** Server handles multiple simultaneous monitoring connections.
* **Modern Interface:** Professional security-themed Tkinter GUI with a tabbed layout.

---

## 🏗️ Architecture



```text
┌─────────────────┐      Heartbeats      ┌─────────────────┐
│   Client (GUI)  │ ───────────────────► │  Server (Vault) │
│   - Log Viewer  │      (Hash values)   │  - Monitoring   │
│   - Monitoring  │ ◄──────────────────  │  - Alerting     │
│   - Analysis    │      Acknowledgments │  - Persistence  │
└─────────────────┘                       └─────────────────┘
```

## Components:
  **Client**: Tkinter GUI application for log viewing and active monitoring.

  **Server**: Background "Vault" process that receives and validates heartbeats.

  **Security Utils**: Core logic for encryption and custom data structures.

  **Storage**: JSON-based persistence for heartbeat history and user credentials.

## 📦 Installation
**Prerequisites**

    Python 3.8 or higher

    pip package manager

**1. Clone the Repository**
```bash
git clone [https://github.com/yourusername/shieldaudit.git](https://github.com/yourusername/shieldaudit.git)
cd shieldaudit
```
**2. Install Dependencies**
```bash
pip install -r requirements.txt
```
**3. Project Structure**
```text
📂 ShieldAudit/
├── 📂 src/
│   ├── main_gui.py          # Main application Entry Point
│   ├── server_vault.py      # Server component
│   └── security_utils.py    # Utilities & Logic
├── 📂 logs/                  # Sample Log storage
├── 📂 server_data/           # Heartbeat persistence
├── 📂 tests/                 # Full Test suite
└── 📄 requirements.txt       # Dependencies
```
## 🚀 Usage Guide
**Starting the Application**
Option 1: Quick Start (GUI only)
```bash
python src/main_gui.py
```
Option 2: Distributed Mode (Recommended)

  Start Server: python src/server_vault.py

  Start Client: python src/main_gui.py
GUI Control Reference
Control	Description
🚀 Start Server	Launches the background server process
🔌 Connect	Establishes connection to the vault
📂 Load Log	Reads the selected log file into the buffer
▶️ Monitor	Begins active integrity heartbeat checks
🔎 Search	Real-time keyword filtering across logs
**👥 User Roles**
```text
Username	Password	Role	Permissions
admin	admin123	Administrator	Full system access & Server control
auditor	audit123	Auditor	View logs and alerts only
analyst	analyze123	Analyst	Search and filter capabilities
```
**🧪 Testing**

The project includes a comprehensive test suite covering GUI, Server, and Security modules.
Bash
```python
# Run all tests
python tests/run_all_tests.py
# Run specific module (security, server, gui, or integration)
python tests/run_all_tests.py --module security
```
🔧 Technical Details
Custom Data Structure: CircularLogBuffer

To ensure memory efficiency, we implemented a custom doubly linked list:
    O(1) insertion and deletion.

    Fixed-size window (last 50 logs).

    Automatic overwrite on buffer overflow.

Heartbeat Schema

Integrity is verified using the following JSON payload:
```json

{
  "log_file": "system_audit.txt",
  "file_hash": "sha256_hash_value",
  "timestamp": "2026-02-14T10:30:00"
}
```
