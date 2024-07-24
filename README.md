# Vulnerability Scanner

A Python-based Vulnerability Scanner designed to detect open ports and scan for common vulnerabilities. This tool provides an easy way to assess the security of your network and applications.

## Features

- **Port Scanning:** Detect open ports on a given IP address or URL.
- **Vulnerability Detection:** Basic checks to identify known vulnerabilities associated with open ports.
- **Progress Display:** Real-time updates on the scanning process.

## Installation

To get started with the Vulnerability Scanner, follow these steps:

1. **Clone the Repository:**

    ```bash
    git clone https://github.com/yourusername/vulnerability-scanner.git
    cd vulnerability-scanner
    ```

2. **Create a Virtual Environment:**

    ```bash
    python -m venv .venv
    ```

3. **Activate the Virtual Environment:**

    - On Windows:

        ```bash
        .venv\Scripts\activate
        ```

    - On macOS/Linux:

        ```bash
        source .venv/bin/activate
        ```

4. **Install the Dependencies:**

    ```bash
    pip install -r requirements.txt
    ```

## Usage

To use the Vulnerability Scanner, follow these steps:

1. **Run the Script:**

    ```bash
    python main.py
    ```

2. **Follow the Prompts:**

    - **Enter the target IP or URL**: Provide the IP address or URL you want to scan.
    - **Choose the type of scan**: Select from port scanning or vulnerability detection.
    - **Review the Results**: The tool will display scanning progress and results.

## Example

```bash
python main.py
Enter the target IP or URL: https://www.example.com
Scanning ports on https://www.example.com...
Open ports: [80, 443]
Vulnerabilities detected: None
