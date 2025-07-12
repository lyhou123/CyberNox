# CyberNox - All-in-One Python Cybersecurity Toolkit

![Python](https://img.shields.io/badge/python-v3.7+-blue.svg)
![Platform](https://img.shields.io/badge/platform-windows%20%7C%20linux%20%7C%20macos-lightgrey.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

CyberNox is a comprehensive cybersecurity toolkit designed for penetration testing, vulnerability assessment, and security research. It provides a modular architecture with various security testing capabilities.

## 🚀 Features

### 🔍 Reconnaissance
- **WHOIS Lookup**: Domain registration information
- **Subdomain Enumeration**: Discover subdomains using wordlists
- **DNS Lookup**: Comprehensive DNS record analysis

### 🔎 Scanning
- **Port Scanning**: Multi-threaded TCP port scanner
- **Service Detection**: Banner grabbing and service fingerprinting
- **SSL/TLS Analysis**: Certificate information and security assessment

### 🛡️ Vulnerability Assessment
- **CVE Database Search**: Look up known vulnerabilities
- **Web Application Testing**: SQL injection, XSS, directory traversal
- **Security Headers Analysis**: Missing security configurations
- **Sensitive File Detection**: Exposed configuration files

### 💥 Exploitation Tools
- **Reverse Shell Generator**: Multiple shell types and encoding options
- **Web Shell Generation**: PHP, ASP, ASPX, JSP web shells
- **Payload Encoding**: Base64, URL encoding support

### 🌐 Web Security
- **Directory Brute Force**: Discover hidden directories and files
- **Phishing Detection**: URL analysis and reputation checking
- **HTTP Security Testing**: Comprehensive web vulnerability scanning

### 📊 Monitoring & Analysis
- **Network Monitoring**: Packet capture and analysis
- **Port Scan Detection**: Identify scanning attempts
- **Traffic Analysis**: Protocol distribution and connection tracking

### 📋 Reporting
- **Multiple Formats**: JSON, XML, CSV, HTML, Text reports
- **Comprehensive Analysis**: Detailed vulnerability summaries
- **Professional Output**: Well-formatted security reports

## 📦 Installation

### Prerequisites
- Python 3.7 or higher
- pip package manager

### Quick Setup
```bash
# Clone the repository
git clone https://github.com/lyhou123/CyberNox.git
cd CyberNox

# Run setup script
python setup.py

# Or install manually
pip install -r requirements.txt
```

### Manual Installation
```bash
pip install requests beautifulsoup4 python-whois colorama pyyaml urllib3 dnspython scapy
```

## 🎯 Usage

### Basic Commands

#### Reconnaissance
```bash
# WHOIS lookup
python main.py recon --whois example.com

# Subdomain enumeration
python main.py recon --subenum example.com

# DNS lookup
python main.py recon --dns example.com
```

#### Port Scanning
```bash
# Scan specific ports
python main.py scan --target 192.168.1.1 --ports 80 443 22

# Scan with custom thread count
python main.py scan --target example.com --ports 21 22 23 25 53 80 443 --threads 100
```

#### Vulnerability Scanning
```bash
# Web vulnerability scan
python main.py vuln --url https://example.com

# CVE lookup
python main.py vuln --service apache
```

#### Directory Brute Force
```bash
# Directory brute force
python main.py brute --url https://example.com/

# Custom wordlist and extensions
python main.py brute --url https://example.com/ --wordlist custom.txt --extensions php txt html
```

#### Reverse Shell Generation
```bash
# Bash reverse shell
python main.py shell --type bash --lhost 192.168.1.100 --lport 4444

# Python reverse shell
python main.py shell --type python3 --lhost 10.0.0.1 --lport 9999

# PowerShell reverse shell
python main.py shell --type powershell --lhost 192.168.1.100 --lport 4444
```

#### Phishing Detection
```bash
# Analyze suspicious URL
python main.py phishing --url https://suspicious-site.com

# Check URL reputation
python main.py phishing --url https://example.com --reputation
```

#### Service Fingerprinting
```bash
# HTTP fingerprinting
python main.py finger --target example.com --http

# SSL certificate analysis
python main.py finger --target example.com --ssl

# Banner grabbing
python main.py finger --target 192.168.1.1 --port 22
```

#### Network Monitoring
```bash
# Basic network monitoring
python main.py monitor --duration 60

# Port scan detection
python main.py monitor --portscan-detect --duration 30

# Monitor specific interface
python main.py monitor --interface eth0 --duration 120
```

### Advanced Usage

#### Output Options
```bash
# Save results to file
python main.py scan --target example.com --ports 80 443 --output scan_results.json

# Different output formats
python main.py vuln --url https://example.com --format html --output report.html
python main.py scan --target 192.168.1.1 --ports 80 443 --format csv --output results.csv
```

#### Verbose Mode
```bash
# Enable detailed logging
python main.py -v scan --target example.com --ports 80 443
```

## 📁 Project Structure

```
CyberNox/
├── main.py                 # Main entry point
├── setup.py               # Setup and installation script
├── requirements.txt       # Python dependencies
├── config.yml            # Configuration file
├── README.md             # This file
├── core/                 # Core modules
│   ├── __init__.py
│   ├── recon.py          # Reconnaissance module
│   ├── scanner.py        # Port scanning and CVE lookup
│   ├── brute.py          # Directory brute force
│   ├── exploit.py        # Exploit and payload generation
│   ├── vulnscan.py       # Web vulnerability scanning
│   ├── phishing.py       # Phishing detection
│   ├── monitor.py        # Network monitoring
│   └── report.py         # Report generation
├── utils/                # Utility modules
│   ├── __init__.py
│   ├── config.py         # Configuration management
│   ├── logger.py         # Logging utilities
│   ├── nettools.py       # Network utilities
│   └── fingerprint.py    # Service fingerprinting
├── data/                 # Data files
│   └── wordlists/        # Wordlist files
│       ├── subdomains.txt
│       ├── directories.txt
│       └── files.txt
└── reports/              # Generated reports (created at runtime)
```

## ⚙️ Configuration

CyberNox uses a YAML configuration file (`config.yml`) for customization:

```yaml
# General Settings
general:
  debug: false
  log_level: INFO
  output_format: json
  max_threads: 10
  timeout: 5

# Network Settings
network:
  user_agent: "CyberNox-Scanner/1.0"
  default_ports: [21, 22, 23, 25, 53, 80, 110, 443, 993, 995, 3389]
  socket_timeout: 3

# Scanning Settings
scan:
  default_threads: 50
  max_ports: 65535
  scan_timeout: 1

# Brute Force Settings
brute:
  directory_wordlist: "data/wordlists/directories.txt"
  max_requests_per_second: 10
  follow_redirects: true
```

## 🔧 Dependencies

### Required
- `requests` - HTTP library
- `beautifulsoup4` - HTML parsing
- `python-whois` - WHOIS lookups
- `colorama` - Colored terminal output
- `pyyaml` - YAML configuration
- `urllib3` - URL handling

### Optional
- `dnspython` - Advanced DNS operations
- `scapy` - Network packet manipulation

## 🛡️ Security Considerations

### Ethical Use Only
CyberNox is designed for:
- ✅ Authorized penetration testing
- ✅ Security research and education
- ✅ Vulnerability assessment of your own systems
- ✅ Bug bounty programs with proper authorization

### Prohibited Uses
- ❌ Unauthorized access to systems
- ❌ Malicious activities
- ❌ Testing systems without permission
- ❌ Any illegal activities

### Disclaimer
This tool is provided for educational and authorized testing purposes only. Users are responsible for ensuring they have proper authorization before using this tool against any systems.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🐛 Bug Reports

If you find any bugs or issues, please report them on the [GitHub Issues](https://github.com/lyhou123/CyberNox/issues) page.

## 📞 Support

For support and questions:
- Create an issue on GitHub
- Check the documentation
- Review the example commands

## 🎓 Educational Resources

CyberNox is designed to be educational. Each module includes detailed comments and documentation to help users understand the security concepts being demonstrated.

---

**⚠️ Remember: Always obtain proper authorization before testing any systems that you do not own!**
