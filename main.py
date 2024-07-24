import socket
import requests
import time


def scan_ports(target_ip, ports):
    print(f"Scanning ports on {target_ip}...")
    open_ports = []
    total_ports = len(ports)
    for index, port in enumerate(ports, start=1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)
        result = sock.connect_ex((target_ip, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
        print(f"Scanning port {port} ({index}/{total_ports})")
        time.sleep(0.1)  # Slight delay for better visibility of progress
    return open_ports


def check_http_methods(target_url):
    print(f"Checking HTTP methods on {target_url}...")
    methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH", "TRACE"]
    allowed_methods = []
    for method in methods:
        try:
            response = requests.request(method, target_url)
            if response.status_code != 405:
                allowed_methods.append(method)
        except requests.exceptions.RequestException:
            pass
    return allowed_methods


def display_results(open_ports, http_methods):
    if open_ports:
        print(f"\nOpen ports found: {', '.join(map(str, open_ports))}")
        print("Potential vulnerabilities detected on the following ports:")
        for port in open_ports:
            print(f" - Port {port}: Open")
    else:
        print("\nNo open ports found.")

    if http_methods:
        print(f"\nAllowed HTTP methods: {', '.join(http_methods)}")
        print("Potential vulnerabilities detected with the following HTTP methods:")
        for method in http_methods:
            print(f" - HTTP Method {method}: Allowed")
    else:
        print("\nNo allowed HTTP methods found or target is not a web server.")


def main():
    target = input("Enter the target IP or URL: ")

    # Check if the target is a URL or an IP
    if target.startswith("http://") or target.startswith("https://"):
        # Extract domain name from the URL
        domain = target.split("//")[1].split("/")[0]
        try:
            target_ip = socket.gethostbyname(domain)
        except socket.gaierror:
            print("Invalid URL or domain name could not be resolved.")
            return
    else:
        target_ip = target

    ports = [21, 22, 23, 25, 80, 110, 143, 443, 3389]

    # Scan ports
    open_ports = scan_ports(target_ip, ports)

    # Check HTTP methods
    http_methods = []
    if target.startswith("http://") or target.startswith("https://"):
        http_methods = check_http_methods(target)

    # Display results
    display_results(open_ports, http_methods)


if __name__ == "__main__":
    main()