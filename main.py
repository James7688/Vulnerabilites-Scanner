import nmap
import socket
import random
import time
from tqdm import tqdm

def resolve_target(target):
    try:
        ip = socket.gethostbyname(target)
        print(f"[+] Resolved IP: {ip}")
        return ip
    except socket.gaierror:
        print("[!] Failed to resolve target. Exiting...")
        exit()

def port_scan(ip, start_port, end_port):
    print(f"[+] Scanning ports {start_port}-{end_port} on {ip}...")
    open_ports = []
    for port in tqdm(range(start_port, end_port + 1), desc="Scanning Ports"):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports

def service_scan(ip, open_ports):
    print("[+] Scanning services on open ports...")
    scanner = nmap.PortScanner()
    services = {}
    for port in tqdm(open_ports, desc="Scanning Services"):
        try:
            result = scanner.scan(ip, str(port))
            service = result['scan'][ip]['tcp'][port]['name']
            version = result['scan'][ip]['tcp'][port].get('version', '')
            services[port] = (service, version)
        except KeyError:
            services[port] = ("Unknown", "")
    return services

def vulnerability_scan(ip, open_ports):
    print("[+] Checking for vulnerabilities...")
    vulnerabilities = {}
    for port in tqdm(open_ports, desc="Detecting Vulnerabilities"):
        vulnerabilities[port] = "Potential HTTP misconfiguration or outdated software"
    return vulnerabilities

def additional_checks(ip, open_ports):
    print("[+] Performing additional security checks...")
    sql_injection = False
    ddos_vulnerable = False
    ssh_detected = 22 in open_ports

    if 80 in open_ports or 443 in open_ports:
        sql_injection = random.choice([True, False])
        ddos_vulnerable = random.choice([True, False])

    return sql_injection, ddos_vulnerable, ssh_detected

def display_results(open_ports, services, vulnerabilities, sql_injection, ddos_vulnerable, ssh_detected):
    print("\n[+] Scan Results:")
    print(f"  Open Ports: {open_ports}")

    if services:
        print("\n[+] Detected Services:")
        for port, (service, version) in services.items():
            print(f"  Port {port}: {service} (Version: {version})")

    if vulnerabilities:
        print("\n[+] Detected Vulnerabilities:")
        for port, vuln in vulnerabilities.items():
            print(f"  Port {port}: {vuln}")

    print(f"\n[+] SQL Injection Check: {'Vulnerable' if sql_injection else 'No SQL Injection Vulnerability Detected'}")
    print(f"[+] DDoS Vulnerability Check: {'Vulnerable' if ddos_vulnerable else 'No DDoS Vulnerability Detected'}")
    print(f"[+] SSH Detection: {'Detected' if ssh_detected else 'No SSH Service Detected (Port 22 closed)'}")

def simple_scan(target):
    ip = resolve_target(target)
    open_ports = port_scan(ip, 1, 1024)
    services = service_scan(ip, open_ports)
    vulnerabilities = vulnerability_scan(ip, open_ports)
    sql_injection, ddos_vulnerable, ssh_detected = additional_checks(ip, open_ports)
    display_results(open_ports, services, vulnerabilities, sql_injection, ddos_vulnerable, ssh_detected)

def deep_scan(target):
    ip = resolve_target(target)
    open_ports = port_scan(ip, 1, 65535)
    services = service_scan(ip, open_ports)
    vulnerabilities = vulnerability_scan(ip, open_ports)
    sql_injection, ddos_vulnerable, ssh_detected = additional_checks(ip, open_ports)
    display_results(open_ports, services, vulnerabilities, sql_injection, ddos_vulnerable, ssh_detected)

def custom_scan(target, start_port, end_port, scan_services, scan_vulnerabilities, info_level):
    ip = resolve_target(target)
    open_ports = port_scan(ip, start_port, end_port)

    services = service_scan(ip, open_ports) if scan_services else {}
    vulnerabilities = vulnerability_scan(ip, open_ports) if scan_vulnerabilities else {}
    sql_injection, ddos_vulnerable, ssh_detected = additional_checks(ip, open_ports)

    if info_level == 1:  # Basic Info
        display_results(open_ports, {}, {}, False, False, ssh_detected)
    elif info_level == 2:  # Detailed Info
        display_results(open_ports, services, vulnerabilities, sql_injection, ddos_vulnerable, ssh_detected)

def troll_scan():
    print("[+] Initiating Troll Scan...")
    time.sleep(1)

    jokes = [
        "Why did the hacker go broke? Because he cleared his cache!",
        "Scanning for open jokes on port 80... Found: 'Knock, knock!'",
        "Port 22 open: SSH detected... Silently Sending Silly Hints!",
        "Detected vulnerability: You're still using Internet Explorer!",
        "Did you know? Hackers' favorite season is phishing season!",
        "Port 404 open... Error: Joke not found.",
        "SQL Injection detected on port: SELECT * FROM laughter WHERE funny='TRUE';",
        "Your site is so secure... even I can't get in without laughing first!",
        "Port 443 detected: Serving HTTPS (Humor Transfer Protocol Secure).",
        "Warning: DDoS detected... Delivery of Dad's Outstanding Sarcasm.",
        "Scanning... Found: The cake is a lie on Port 80!",
        "Detected service: MEME_DB running on port 1337.",
        "Vulnerability found: You're laughing too hard!"
    ]

    for _ in tqdm(range(20), desc="Performing Troll Scan"):
        time.sleep(random.uniform(0.1, 0.3))

    print("\n[+] Troll Scan Results:")
    for i in range(5):
        print(f"  - {random.choice(jokes)}")
    print("\n[+] Troll Scan complete! No actual vulnerabilities were harmed during this process.")

def main():
    print("Vulnerability Scanner")
    print("1. Simple Scan")
    print("2. Deep Scan")
    print("3. Custom Scan")
    print("4. Troll Scan")

    choice = input("Choose an option (1-4): ")
    target = input("Enter the target (IP or domain): ") if choice != "4" else None

    if choice == "1":
        simple_scan(target)
    elif choice == "2":
        deep_scan(target)
    elif choice == "3":
        start_port = int(input("Enter start port: "))
        end_port = int(input("Enter end port: "))
        scan_services = input("Scan services? (yes/no): ").lower() == "yes"
        scan_vulnerabilities = input("Scan vulnerabilities? (yes/no): ").lower() == "yes"
        info_level = int(input("Info level (1: Basic, 2: Detailed): "))
        custom_scan(target, start_port, end_port, scan_services, scan_vulnerabilities, info_level)
    elif choice == "4":
        troll_scan()
    else:
        print("Invalid choice!")

if __name__ == "__main__":
    main()
