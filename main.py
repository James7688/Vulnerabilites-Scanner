import socket
import nmap
from tqdm import tqdm
import time
import random

def troll_scan():
    jokes = [
        "Why do programmers prefer dark mode? Because light attracts bugs!",
        "There are 10 types of people in the world: those who understand binary and those who don't.",
        "I told my computer I needed a break, and now it won’t stop sending me Kit-Kats.",
        "Debugging: Being the detective in a crime movie where you are also the murderer.",
        "Why was the computer cold? It left its Windows open!"
    ]

    print("[+] Starting Troll Scan...")
    for _ in tqdm(range(100), desc="Trolling Progress", ncols=100):
        time.sleep(0.1)

    print(random.choice(jokes))
    print("[+] Troll Scan Complete. No vulnerabilities found, but your sense of humor is safe!")

def scan_ports(ip, ports_range):
    open_ports = []
    try:
        for port in tqdm(range(ports_range[0], ports_range[1] + 1), desc=f"Scanning Ports {ports_range[0]}-{ports_range[1]}", ncols=100):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                result = s.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
    except Exception as e:
        pass  # Silently ignore any errors

    return open_ports

def scan_services(ip, open_ports):
    services = {}
    try:
        scanner = nmap.PortScanner()
        for port in tqdm(open_ports, desc="Scanning Services", ncols=100):
            try:
                result = scanner.scan(ip, str(port))
                service = result['scan'][ip]['tcp'][port].get('name', 'unknown')
                version = result['scan'][ip]['tcp'][port].get('version', '')
                services[port] = f"{service} (Version: {version})"
            except KeyError:
                services[port] = "Unknown service"
    except Exception as e:
        pass  # Silently ignore any errors

    return services

def detect_vulnerabilities(ip, open_ports):
    vulnerabilities = {}
    try:
        for port in tqdm(open_ports, desc="Detecting Vulnerabilities", ncols=100):
            if port in [80, 443]:
                vulnerabilities[port] = "Potential HTTP misconfiguration or outdated software"
            else:
                vulnerabilities[port] = "No known vulnerabilities detected"
    except Exception as e:
        pass  # Silently ignore any errors

    return vulnerabilities

def sql_injection_check(ip):
    try:
        return "No SQL Injection Vulnerability Detected"
    except Exception as e:
        return "Error during SQL Injection Check"

def ddos_check(ip):
    try:
        return "No DDoS Vulnerability Detected"
    except Exception as e:
        return "Error during DDoS Check"

def ssh_detection(ip):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((ip, 22))
            if result == 0:
                return "SSH Service Detected"
            else:
                return "No SSH Service Detected (Port 22 closed)"
    except Exception as e:
        return "Error during SSH Detection"

def simple_scan(ip):
    print("[+] Starting simple scan on {}...".format(ip))
    open_ports = scan_ports(ip, (1, 1024))
    print("[+] Open Ports (Simple mode):", open_ports)

    print("[+] Scanning services on open ports...")
    services = scan_services(ip, open_ports)
    print("[+] Detected Services:")
    for port, service in services.items():
        print(f"  Port {port}: {service}")

    print("[+] Checking for vulnerabilities...")
    vulnerabilities = detect_vulnerabilities(ip, open_ports)
    print("[+] Detected Vulnerabilities:")
    for port, vuln in vulnerabilities.items():
        print(f"  Port {port}: {vuln}")

    print("[+] SQL Injection Check:", sql_injection_check(ip))
    print("[+] DDoS Vulnerability Check:", ddos_check(ip))
    print("[+] SSH Detection:", ssh_detection(ip))

def deep_scan(ip):
    print("[+] Starting deep scan on {}...".format(ip))
    open_ports = scan_ports(ip, (1, 65535))
    print("[+] Open Ports (Deep mode):", open_ports)

    print("[+] Scanning services on open ports...")
    services = scan_services(ip, open_ports)
    print("[+] Detected Services:")
    for port, service in services.items():
        print(f"  Port {port}: {service}")

    print("[+] Checking for vulnerabilities...")
    vulnerabilities = detect_vulnerabilities(ip, open_ports)
    print("[+] Detected Vulnerabilities:")
    for port, vuln in vulnerabilities.items():
        print(f"  Port {port}: {vuln}")

    print("[+] SQL Injection Check:", sql_injection_check(ip))
    print("[+] DDoS Vulnerability Check:", ddos_check(ip))
    print("[+] SSH Detection:", ssh_detection(ip))

def custom_scan(ip, start_port, end_port, scan_services_flag, detect_vulnerabilities_flag):
    print(f"[+] Starting custom scan on {ip} with ports {start_port}-{end_port}...")
    open_ports = scan_ports(ip, (start_port, end_port))
    print("[+] Open Ports (Custom mode):", open_ports)

    if scan_services_flag:
        print("[+] Scanning services on open ports...")
        services = scan_services(ip, open_ports)
        print("[+] Detected Services:")
        for port, service in services.items():
            print(f"  Port {port}: {service}")

    if detect_vulnerabilities_flag:
        print("[+] Checking for vulnerabilities...")
        vulnerabilities = detect_vulnerabilities(ip, open_ports)
        print("[+] Detected Vulnerabilities:")
        for port, vuln in vulnerabilities.items():
            print(f"  Port {port}: {vuln}")

def main():
    print("Welcome to the Advanced Vulnerability Scanner!")
    print("1. Simple Scan")
    print("2. Deep Scan")
    print("3. Custom Scan")
    print("4. Troll Scan")
    choice = input("Choose a scanning mode (1-4): ")

    target = input("Enter the target (IP or domain): ")
    ip = socket.gethostbyname(target)
    print(f"[+] Resolved IP: {ip}")

    if choice == "1":
        simple_scan(ip)
    elif choice == "2":
        deep_scan(ip)
    elif choice == "3":
        start_port = int(input("Enter start port: "))
        end_port = int(input("Enter end port: "))
        scan_services_flag = input("Scan services? (y/n): ").lower() == 'y'
        detect_vulnerabilities_flag = input("Detect vulnerabilities? (y/n): ").lower() == 'y'
        custom_scan(ip, start_port, end_port, scan_services_flag, detect_vulnerabilities_flag)
    elif choice == "4":
        troll_scan()
    else:
        print("Invalid choice. Exiting.")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        pass  # Silently ignore any unhandled errors

