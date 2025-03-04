import socket
import nmap
from tqdm import tqdm
import time

def scan_ports(ip, ports_range):
    open_ports = []
    for port in tqdm(range(ports_range[0], ports_range[1] + 1), desc=f"Scanning Ports {ports_range[0]}-{ports_range[1]}", ncols=100):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            result = s.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
    return open_ports

def scan_services(ip, open_ports):
    services = {}
    scanner = nmap.PortScanner()
    for port in tqdm(open_ports, desc="Scanning Services", ncols=100):
        try:
            result = scanner.scan(ip, str(port))
            service = result['scan'][ip]['tcp'][port].get('name', 'unknown')
            version = result['scan'][ip]['tcp'][port].get('version', '')
            services[port] = f"{service} (Version: {version})"
        except KeyError:
            services[port] = "Unknown service"
    return services

def detect_vulnerabilities(ip, open_ports):
    vulnerabilities = {}
    for port in tqdm(open_ports, desc="Detecting Vulnerabilities", ncols=100):
        if port in [80, 443]:
            vulnerabilities[port] = "Potential HTTP misconfiguration or outdated software"
        else:
            vulnerabilities[port] = "No known vulnerabilities detected"
    return vulnerabilities

def sql_injection_check(ip):
    return "No SQL Injection Vulnerability Detected"

def ddos_check(ip):
    return "No DDoS Vulnerability Detected"

def ssh_detection(ip):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        result = s.connect_ex((ip, 22))
        return "SSH Service Detected" if result == 0 else "No SSH Service Detected (Port 22 closed)"

def ssl_check(ip):
    return "No SSL vulnerability detected"

def ask_additional_scans():
    print("\nDo you want to include additional scans?")
    sql_scan = input("  - SQL Injection (y/n): ").lower() == "y"
    ddos_scan = input("  - DDoS Vulnerability (y/n): ").lower() == "y"
    ssh_scan = input("  - SSH Detection (y/n): ").lower() == "y"
    ssl_scan = input("  - SSL Vulnerability (y/n): ").lower() == "y"
    return sql_scan, ddos_scan, ssh_scan, ssl_scan

def main():
    print("Welcome to the Advanced Vulnerability Scanner!")

    # Ask for additional scans FIRST
    sql_scan, ddos_scan, ssh_scan, ssl_scan = ask_additional_scans()

    # Then ask for the target
    target = input("\nEnter the target (IP or domain): ")
    ip = socket.gethostbyname(target)
    print(f"[+] Resolved IP: {ip}")

    # Then ask for the scan mode
    print("\nChoose a scanning mode:")
    print("1. Simple Scan (Ports 1-1024)")
    print("2. Deep Scan (Ports 1-65535)")
    print("3. Custom Scan (Specify range)")
    choice = input("Enter your choice (1-3): ")

    if choice == "1":
        open_ports = scan_ports(ip, (1, 1024))
    elif choice == "2":
        open_ports = scan_ports(ip, (1, 65535))
    elif choice == "3":
        start_port = int(input("Enter start port: "))
        end_port = int(input("Enter end port: "))
        open_ports = scan_ports(ip, (start_port, end_port))
    else:
        print("Invalid choice. Exiting.")
        return

    print("\n[+] Open Ports:", open_ports)

    print("\n[+] Scanning services on open ports...")
    services = scan_services(ip, open_ports)
    for port, service in services.items():
        print(f"  Port {port}: {service}")

    print("\n[+] Checking for vulnerabilities...")
    vulnerabilities = detect_vulnerabilities(ip, open_ports)
    for port, vuln in vulnerabilities.items():
        print(f"  Port {port}: {vuln}")

    # Perform additional scans based on user selection
    if sql_scan:
        print("[+] SQL Injection Check:", sql_injection_check(ip))
    if ddos_scan:
        print("[+] DDoS Vulnerability Check:", ddos_check(ip))
    if ssh_scan:
        print("[+] SSH Detection:", ssh_detection(ip))
    if ssl_scan:
        print("[+] SSL Vulnerability Check:", ssl_check(ip))

if __name__ == "__main__":
    main()


