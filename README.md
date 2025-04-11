# SwiftJaguar's Swifty Vulnerability Scanner 🐆

A powerful network scanning and vulnerability assessment tool built in Python. This tool helps you discover devices on your network, scan for open ports, and identify potential security vulnerabilities.

## Features 🌟

- **Network Discovery**: Automatically detects and maps all devices on your local network
- **Port Scanning**: Checks for open ports and identifies running services
- **Vulnerability Assessment**: Identifies known vulnerable versions of common services
- **Geolocation**: Provides geolocation information for public IP addresses
- **Multiple Scanning Modes**:
  - Single target scan
  - Full network scan
  - Current device scan
  - Custom port range scan

## Prerequisites 📋

- Python 3.7 or higher
- Nmap installed on your system ([Download Nmap](https://nmap.org/download.html))
- Administrator/root privileges for full scanning capabilities

## Installation 🔧

1. Clone this repository:
```bash
git clone https://github.com/yourusername/swifty-scanner.git
cd swifty-scanner
```

2. Install required Python packages:
```bash
pip install -r requirements.txt
```

3. Ensure Nmap is installed on your system:
   - **Windows**: Download and install from [Nmap website](https://nmap.org/download.html)
   - **Linux**: `sudo apt-get install nmap`
   - **macOS**: `brew install nmap`

## Usage 🚀

Run the scanner:
```bash
python scanner.py
```

### Available Scan Options:

1. **Specific Target Scan**
   - Scans a specific IP or domain
   - Checks common vulnerable ports
   - Provides service version detection

2. **Network Device Discovery**
   - Maps all devices on your local network
   - Shows IP addresses and hostnames
   - Option to perform detailed scans on discovered devices

3. **Current Device Scan**
   - Scans your own device for open ports
   - Identifies running services
   - Checks for vulnerabilities

4. **Custom Port Range Scan**
   - Specify custom ports to scan
   - Supports individual ports (80)
   - Supports port ranges (80-443)
   - Supports multiple ports (80,443,8080)

## Features Breakdown 📊

### Port Scanning
- Scans common ports (21, 22, 23, 25, 53, 80, etc.)
- Detects service versions
- Identifies vulnerable service versions

### Network Discovery
- Automatic network range detection
- Device hostname resolution
- Active host detection

### Security Features
- Rate limiting to prevent network flooding
- Progress indicators for long operations
- Detailed scan results saved to JSON files

### Reporting
- Rich console output with color coding
- Structured JSON result storage
- Geolocation information for public IPs

## Output Examples 📝

```
🔍 Discovered Devices
┌────────────────┬────────┬───────────────┐
│   IP Address   │ Status │   Hostname    │
├────────────────┼────────┼───────────────┤
│ 192.168.1.1    │   Up   │ router.local  │
│ 192.168.1.100  │   Up   │ laptop.local  │
└────────────────┴────────┴───────────────┘
```

## Security Considerations ⚠️

- Always obtain permission before scanning networks you don't own
- Some networks may block or flag scanning activities
- Use responsibly and ethically
- Consider local laws and regulations regarding network scanning

## Troubleshooting 🔍

### Common Issues:

1. **No devices found**
   - Check if you have admin/root privileges
   - Verify firewall settings
   - Ensure you're connected to the network

2. **Scan permission errors**
   - Run with administrator privileges
   - Check antivirus settings
   - Verify Nmap installation

3. **Rate limiting messages**
   - Wait a few minutes between scans
   - Reduce scan frequency
   - Adjust rate limiter settings if needed

## Contributing 🤝

Contributions are welcome! Please feel free to submit pull requests.

## License 📄

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments 🙏

- Built with Python and Nmap
- Uses Rich for beautiful console output
- Inspired by the need for better network visibility
