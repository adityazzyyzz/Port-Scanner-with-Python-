#!/usr/bin/env python3
"""
final.py - Port scanner (famous ports / range) with optional target defaulting to localhost.
Usage:
  python final.py --famous
  python final.py 192.168.1.10 --famous
  python final.py --range 1 1024 --threads 200
"""

import socket
import threading
import argparse
import psutil
from queue import Queue
from colorama import Fore, Style, init

init(autoreset=True)

# ----------------------------------------------------
FAMOUS_PORTS = {
    20: "FTP Data", 21: "FTP Control", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP Server", 68: "DHCP Client", 69: "TFTP", 80: "HTTP",
    110: "POP3", 123: "NTP", 135: "MS RPC", 137: "NetBIOS Name Service",
    138: "NetBIOS Datagram", 139: "NetBIOS Session", 143: "IMAP", 161: "SNMP",
    162: "SNMP Trap", 389: "LDAP", 443: "HTTPS", 445: "Microsoft SMB",
    465: "SMTPS", 514: "Syslog", 587: "SMTP (TLS)", 631: "IPP (Printing)",
    993: "IMAPS", 995: "POP3S", 1080: "SOCKS Proxy", 1433: "MSSQL",
    1521: "Oracle", 1723: "PPTP", 2049: "NFS", 2181: "Zookeeper",
    2375: "Docker", 3000: "Dev Web Apps", 3306: "MySQL", 3389: "RDP",
    3690: "Subversion", 4000: "Game Servers", 5000: "Flask/API", 5432: "PostgreSQL",
    5672: "RabbitMQ", 5900: "VNC", 5984: "CouchDB", 6379: "Redis",
    6667: "IRC", 8000: "Alternate HTTP", 8080: "HTTP Proxy", 8443: "Alt HTTPS",
    9000: "SonarQube", 9090: "Jetty/JBoss", 9200: "Elasticsearch",
    11211: "Memcached", 27017: "MongoDB",
}
# ----------------------------------------------------

print_lock = threading.Lock()

def safe_print(*args, **kwargs):
    with print_lock:
        print(*args, **kwargs)

def get_service_name(port):
    try:
        return socket.getservbyport(port, "tcp")
    except:
        return "Unknown"

def get_local_process(port):
    """Return local process listening on TCP 'port' using psutil; else 'N/A (remote)'."""
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.laddr and conn.laddr.port == port and conn.status == 'LISTEN':
                try:
                    p = psutil.Process(conn.pid)
                    return f"{conn.pid}: {p.name()}"
                except Exception:
                    return f"{conn.pid}: <access denied>"
    except Exception:
        pass
    return "N/A (remote)"

def tcp_scan(ip, port, timeout=0.5):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
        sock.close()
        return True
    except:
        return False

def worker(queue, ip, timeout, results, local_scan):
    while True:
        try:
            port = queue.get_nowait()
        except:
            break

        open_status = tcp_scan(ip, port, timeout)
        service = FAMOUS_PORTS.get(port, get_service_name(port))
        app = get_local_process(port) if local_scan else "N/A (remote)"

        color = Fore.GREEN if open_status else Fore.RED
        status = "open" if open_status else "closed"

        safe_print(f"{color}Port {port:<6} | {status:<6} | Service: {service:<20} | App: {app}")
        results.append((port, status, service, app))
        queue.task_done()

def main():
    parser = argparse.ArgumentParser(description="final.py - Port scanner (defaults to localhost)")
    # make target optional with nargs='?' and default to localhost
    parser.add_argument("target", nargs='?', default="127.0.0.1", help="Target IP or hostname (default: 127.0.0.1)")
    parser.add_argument("--famous", action="store_true", help="Scan only famous/common ports")
    parser.add_argument("--range", nargs=2, type=int, metavar=("START", "END"), help="Scan custom port range")
    parser.add_argument("--threads", type=int, default=100, help="Number of threads")
    parser.add_argument("--timeout", type=float, default=0.8, help="Timeout per port (seconds)")
    args = parser.parse_args()

    try:
        ip = socket.gethostbyname(args.target)
    except Exception as e:
        safe_print(Fore.RED + f"Unable to resolve target '{args.target}': {e}")
        return

    local_scan = ip.startswith("127.") or ip.lower() == "localhost"

    # pick ports
    if args.famous:
        ports = sorted(FAMOUS_PORTS.keys())
    elif args.range:
        start, end = args.range
        if start < 1: start = 1
        if end < start: end = start
        ports = list(range(start, end + 1))
    else:
        safe_print(Fore.RED + "Please specify --famous or --range START END")
        return

    safe_print(Fore.YELLOW + f"Scanning {ip} on {len(ports)} ports with {args.threads} threads (timeout {args.timeout}s)")

    q = Queue()
    for p in ports: q.put(p)

    results = []
    workers = []
    for _ in range(max(1, args.threads)):
        t = threading.Thread(target=worker, args=(q, ip, args.timeout, results, local_scan))
        t.daemon = True
        t.start()
        workers.append(t)

    q.join()
    safe_print(Style.BRIGHT + Fore.CYAN + f"\n[+] Scan complete: {len(ports)} ports scanned on {ip}.")

if __name__ == "__main__":
    main()
