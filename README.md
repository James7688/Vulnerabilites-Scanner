# Vulnerability Scanner

## Overview

The **Vulnerability Scanner** is an advanced Python-based tool designed to scan websites and servers for open ports, detect services, and identify potential security vulnerabilities. It offers multiple scanning modes to suit different needs, from quick scans to in-depth security analysis.

## Features

- **Deep Scan Mode**: Scans all 65,535 ports for a comprehensive security check.
- **Simple Scan Mode**: Scans only the most common 1,024 ports for a quicker analysis.
- **Custom Scan Mode**: Allows users to define a specific port range and select what information to retrieve.
- **Troll Scan Mode**: A fun mode that displays humorous messages and famous internet memes while scanning.
- **Error Handling**: Ensures that all errors are ignored so the scan completes without interruptions.
- **Security Analysis**:
  - Detects open ports and running services.
  - Identifies potential vulnerabilities (e.g., outdated software, misconfigurations).
  - Checks for SQL Injection and DDoS vulnerabilities.
  - Detects SSH availability.

## Installation

### Prerequisites

Ensure you have **Python 3.x** installed. Then, install the required dependencies:

```sh
pip install -r requirements.txt
```

### Required Packages

The following Python packages are required:

- `nmap`
- `requests`
- `progressbar`
- `colorama`
- `beautifulsoup4`
- `urllib3`

## Usage

Run the script and follow the prompts:

```sh
python main.py
```

### Scan Modes

- **Deep Scan**: Comprehensive scan (slow but detailed).
- **Simple Scan**: Quick scan for basic security checks.
- **Custom Scan**: Define your own scan settings.
- **Troll Scan**: A fun scan mode with jokes.

### Example Usage

```sh
Enter the target (IP or domain): example.com
Choose scan mode: 
  1 - Deep Scan
  2 - Simple Scan
  3 - Custom Scan
  4 - Troll Scan
```

## Disclaimer

This tool is intended for ethical security testing and educational purposes only. **Do not use it to scan systems without permission.** Unauthorized scanning may be illegal in some jurisdictions.

## Credit
Quy Anh Nguyen - Developer
