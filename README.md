# Network Port Scanner

A multi-threaded TCP port scanner built in Python — a networking/cybersecurity project that teaches the fundamentals behind tools like **Nmap**.

> ⚠️ **Legal & Ethical Notice**
> Only scan hosts you **own** or have **explicit written permission** to test — e.g. `127.0.0.1` (your own machine), a local VM, or a lab environment like [scanme.nmap.org](https://scanme.nmap.org) (Nmap's own official test target). Scanning systems without authorization is illegal in most jurisdictions and violates most Terms of Service.

## Features

- Scans a target host for **open TCP ports**
- Supports **port ranges** (`1-1024`) or **comma-separated lists** (`22,80,443`)
- **Multi-threaded** for fast scanning
- Identifies common services (SSH, HTTP, HTTPS, MySQL, RDP, etc.) by port number
- Configurable timeout and thread count

##The "why?"
Port scanning is a foundational networking/recon concept in cybersecurity. This project demonstrates:
- Understanding of the **TCP three-way handshake** and how `connect()` scanning works
- Practical use of Python's `socket` and `threading` modules
- Awareness of **responsible/authorized** security testing practices

## Getting Started

### Requirements
- Python 3.7+ (standard library only — no dependencies)

### Installation
```bash
git clone https://github.com/yourusername/port-scanner.git
cd port-scanner
```

### Usage

Scan your own machine's most common ports:
```bash
python port_scanner.py 127.0.0.1 --ports 1-1024
```

Scan specific ports:
```bash
python port_scanner.py 127.0.0.1 --ports 22,80,443,8080
```

Scan Nmap's official public test target (safe and authorized for testing):
```bash
python port_scanner.py scanme.nmap.org --ports 1-1000
```

### Example Output
```
=======================================================
 Scanning target: 127.0.0.1 (127.0.0.1)
 Ports to scan  : 1024
 Started at     : 2026-09-08 10:15:32
=======================================================
  [OPEN] Port 22     (SSH)
  [OPEN] Port 80     (HTTP)
-------------------------------------------------------
Scan complete. 2 open port(s) found: [22, 80]
=======================================================
```

## Project Structure
```
port-scanner/
├── port_scanner.py   # Main script
└── README.md
```

