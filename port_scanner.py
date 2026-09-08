#!/usr/bin/env python3
"""
Network Port Scanner
----------------------
A beginner cybersecurity/networking tool that scans a target host for
open TCP ports using Python's socket library. Built for learning how
port scanning works at a fundamental level — no external dependencies.

IMPORTANT / LEGAL NOTICE:
Only scan hosts you own or have explicit permission to test
(e.g. localhost, your own home lab/router, or a machine you control).
Scanning systems without authorization may be illegal in your jurisdiction.

Usage:
    python port_scanner.py 127.0.0.1
    python port_scanner.py scanme.example.com --ports 1-1024
    python port_scanner.py 127.0.0.1 --ports 22,80,443,8080
"""

import argparse
import socket
import sys
import threading
from datetime import datetime
from queue import Queue

# A short list of well-known ports for friendlier output
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-Alt",
}

print_lock = threading.Lock()


def parse_ports(port_arg: str):
    """Parse a port argument like '1-1024' or '22,80,443' into a list of ints."""
    ports = set()
    for part in port_arg.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            ports.update(range(int(start), int(end) + 1))
        elif part:
            ports.add(int(part))
    return sorted(ports)


def scan_port(target_ip: str, port: int, timeout: float, open_ports: list):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((target_ip, port))
        if result == 0:
            service = COMMON_PORTS.get(port, "unknown")
            with print_lock:
                print(f"  [OPEN] Port {port:<6} ({service})")
            open_ports.append(port)
    except socket.error:
        pass
    finally:
        sock.close()


def worker(target_ip, timeout, q: Queue, open_ports: list):
    while not q.empty():
        port = q.get()
        scan_port(target_ip, port, timeout, open_ports)
        q.task_done()


def run_scan(target: str, ports, timeout: float = 0.5, thread_count: int = 100):
    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"[!] Could not resolve host: {target}")
        sys.exit(1)

    print("=" * 55)
    print(f" Scanning target: {target} ({target_ip})")
    print(f" Ports to scan  : {len(ports)}")
    print(f" Started at     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 55)

    q = Queue()
    for port in ports:
        q.put(port)

    open_ports = []
    threads = []
    for _ in range(min(thread_count, len(ports)) or 1):
        t = threading.Thread(target=worker, args=(target_ip, timeout, q, open_ports))
        t.daemon = True
        t.start()
        threads.append(t)

    q.join()

    print("-" * 55)
    if open_ports:
        print(f"Scan complete. {len(open_ports)} open port(s) found: {sorted(open_ports)}")
    else:
        print("Scan complete. No open ports found in the given range.")
    print("=" * 55)


def main():
    parser = argparse.ArgumentParser(
        description="Scan a host for open TCP ports (educational use on authorized hosts only).",
    )
    parser.add_argument("target", help="Target hostname or IP address (e.g. 127.0.0.1)")
    parser.add_argument(
        "--ports", "-p", default="1-1024",
        help="Ports to scan, e.g. '1-1024' or '22,80,443' (default: 1-1024)",
    )
    parser.add_argument(
        "--timeout", "-t", type=float, default=0.5,
        help="Socket timeout in seconds per port (default: 0.5)",
    )
    parser.add_argument(
        "--threads", type=int, default=100,
        help="Number of concurrent threads (default: 100)",
    )
    args = parser.parse_args()

    ports = parse_ports(args.ports)
    run_scan(args.target, ports, timeout=args.timeout, thread_count=args.threads)


if __name__ == "__main__":
    main()
