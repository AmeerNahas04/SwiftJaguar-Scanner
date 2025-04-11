import nmap  # Main network scanning tool
import socket  # For network operations and getting host information
import os  # For executing system commands and file operations
import platform  # For detecting the operating system
import json # For saving and loading scan results
import requests  # For making HTTP requests to geolocation API
import ipaddress # For IP address validation and checking
import datetime # For timestamps and rate limiting
from pathlib import Path # For cross-platform file path handling
# Rich library components for enhanced terminal output
from rich.console import Console  # For styled console output
from rich.panel import Panel  # For creating boxed panels
from rich.table import Table  # For creating formatted tables
from rich.progress import Progress, SpinnerColumn, TextColumn  # For progress indicators
from rich import box
from typing import Dict, Any # For type hints in function signatures

# Create a directory to store scan results if it doesn't exist
RESULTS_DIR = Path("scan_results")
RESULTS_DIR.mkdir(exist_ok=True)  # exist_ok=True prevents errors if directory exists

# Verify nmap is installed and accessible
try:
    scanner = nmap.PortScanner()  # Try to create scanner object
except nmap.PortScannerError:
    print("Error: Nmap is not installed or not found. Please install it first with pip install python-nmap.")
    exit(1)  # Exit if nmap isn't available

# Initialize console for rich text output
console = Console()

# ASCII art logo for the program interface
jaguar_logo = """ 
       🐆        /\_/\      🐆
 🐆             ( o.o )              🐆
          🐆     > ^ <     🐆
  🐆             🐆                🐆
"""

# Program title
title = "SwiftJaguar's Swifty Vulnerability Scanner"

# Display the banner with logo and title
console.print(Panel.fit(f"[bold yellow]{jaguar_logo}[/bold yellow]\n[bold red]{title}[/bold red]", title="SwiftJaguar"))

# Dictionary of commonly used ports and their services
# These ports are often targeted in security scans
common_ports = {
    21: "FTP (File Transfer Protocol)",  # File transfer service
    22: "SSH (Secure Shell)",  # Secure remote access
    23: "Telnet (Unsecure Remote Login)",  # Insecure remote access (avoid using)
    25: "SMTP (Mail Server)",  # Email sending service
    53: "DNS (Domain Name System)",  # Domain name resolution
    80: "HTTP (Web Traffic)",  # Web server
    110: "POP3 (Email Protocol)",  # Email receiving
    139: "NetBIOS (Windows File Sharing)",  # Windows networking
    143: "IMAP (Email Protocol)",  # Email synchronization
    445: "SMB (Windows File Sharing)",  # Windows file sharing
    1433: "MSSQL (Microsoft SQL Server)",  # Microsoft database
    1521: "Oracle Database",  # Oracle database
    3306: "MySQL/MariaDB",  # MySQL database
    3389: "RDP (Remote Desktop Protocol)",  # Remote desktop access
    5432: "PostgreSQL",  # PostgreSQL database
    6379: "Redis",  # Redis database
    8080: "HTTP Proxy",  # Web proxy
    27017: "MongoDB",  # MongoDB database
    11211: "Memcached",  # Memory caching system
    9200: "Elasticsearch"  # Search engine
}

# Dictionary of known vulnerable versions of common services
# Used to identify if scanned services are running vulnerable versions
VULNERABLE_VERSIONS = {
    'OpenSSH': ['7.2p1', '7.2', '7.1p1', '7.1'],  # Vulnerable SSH versions
    'ProFTPD': ['1.3.5'],  # Vulnerable FTP server versions
    'Apache': ['2.4.49', '2.4.48', '2.4.47'],  # Vulnerable Apache versions
    'Nginx': ['1.16.1', '1.16.0'],  # Vulnerable Nginx versions
    'MySQL': ['5.6.', '5.5.'],  # Vulnerable MySQL versions
    'Redis': ['4.0.', '3.2.'],  # Vulnerable Redis versions
}

def check_version_vulnerability(service: str, version: str) -> str:
    """Check if a service version is known to be vulnerable.
    
    Args:
        service (str): Name of the service to check
        version (str): Version number to check
        
    Returns:
        str: Warning message if vulnerable, empty string if not
    """
    for service_name, vulnerable_versions in VULNERABLE_VERSIONS.items():
        if service_name.lower() in service.lower():
            for vuln_version in vulnerable_versions:
                if version.startswith(vuln_version):
                    return f"⚠️ Known vulnerable version {version} of {service_name}"
    return ""

class RateLimiter:
    """Rate limiting class to prevent too many requests in a short time period."""
    
    def __init__(self, max_requests: int = 100, time_window: int = 60):
        """Initialize rate limiter.
        
        Args:
            max_requests (int): Maximum number of requests allowed in time window
            time_window (int): Time window in seconds
        """
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests = []  # List to store request timestamps

    def add_request(self):
        """Add a new request and check if rate limit is exceeded."""
        current_time = datetime.datetime.now()
        # Remove requests older than the time window
        self.requests = [req_time for req_time in self.requests 
                        if (current_time - req_time).seconds <= self.time_window]
        
        # Check if we've hit the rate limit
        if len(self.requests) >= self.max_requests:
            raise Exception(f"Rate limit exceeded. Maximum {self.max_requests} requests per {self.time_window} seconds.")
        
        self.requests.append(current_time)

# Create a global rate limiter instance
rate_limiter = RateLimiter()

def get_local_network():
    """Detects the local network range (e.g., 192.168.1.0/24).
    
    Returns:
        str: Network range or error message
    """
    try:
        # Create temporary connection to get local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # Connect to Google DNS
        local_ip = s.getsockname()[0]  # Get our IP address
        s.close()
        # Convert IP to network range (e.g., 192.168.1.100 -> 192.168.1.0/24)
        network_range = ".".join(local_ip.split(".")[:3]) + ".0/24"
        return network_range
    except Exception as e:
        return f"Error: {e}"

def get_router_ip():
    """Get the router's IP address (default gateway).
    
    Returns:
        str or None: Router IP address if found, None otherwise
    """
    system_platform = platform.system()  # Get current OS

    if system_platform == "Windows":
        # Windows: use ipconfig command
        gateway = os.popen('ipconfig').read()
        
        # Parse ipconfig output to find default gateway
        lines = gateway.splitlines()
        for i in range(len(lines)):
            if "Default Gateway" in lines[i]:
                try:
                    router_ip = lines[i].split(":")[1].strip()
                    if router_ip:
                        return router_ip
                except IndexError:
                    continue
    else:
        # Linux/Mac: use netstat or ip route
        gateway = os.popen('netstat -rn' if system_platform == "Darwin" else 'ip route').read()
        for line in gateway.splitlines():
            if "default" in line:
                router_ip = line.split()[2]
                return router_ip

    return None

def geo_lookup(ip):
    """Gets geolocation info for a given IP if it's public.
    
    Args:
        ip (str): IP address to look up
    """
    try:
        # Skip private (local) IP addresses
        if ipaddress.ip_address(ip).is_private:
            console.print("[bold yellow]Skipping geolocation: Private IP address[/bold yellow]")
            return

        # Query ip-api.com for location data
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = response.json()

        # Check if the API request was successful
        if data.get("status") != "success":
            msg = data.get("message", "Unknown error")
            console.print(f"[bold red]Geolocation lookup failed:[/bold red] {msg}")
            return

        # Create and display a table with the location information
        table = Table(title=f"🌐 Geolocation for {ip}", title_style="bold cyan")
        table.add_column("Field", style="bold green")
        table.add_column("Value", style="white")

        # Add location data to table
        table.add_row("City", data.get("city", "—"))
        table.add_row("Region", data.get("regionName", "—"))
        table.add_row("Country", data.get("country", "—"))
        table.add_row("ISP", data.get("isp", "—"))
        table.add_row("Org", data.get("org", "—"))

        console.print(table)

    except Exception as e:
        console.print(f"[bold red]Error fetching geolocation:[/bold red] {e}")

def save_scan_results(target: str, results: Dict[str, Any]) -> None:
    """Save scan results to a JSON file.
    
    Args:
        target (str): Target IP or hostname
        results (Dict[str, Any]): Scan results to save
    """
    # Create filename with timestamp
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = RESULTS_DIR / f"scan_{target}_{timestamp}.json"
    
    # Save results with pretty formatting
    with open(filename, 'w') as f:
        json.dump(results, f, indent=4)
    console.print(f"[bold green]Results saved to: {filename}[/bold green]")

def scan_target(target):
    """Scans a given target IP for common vulnerable ports.
    
    Args:
        target (str): IP address or hostname to scan
        
    Returns:
        dict: Scan results or None if rate limit exceeded
    """
    # Check rate limit before scanning
    try:
        rate_limiter.add_request()
    except Exception as e:
        console.print(f"[bold red]{str(e)}[/bold red]")
        return None

    console.print(f"[bold red]Scanning {target} for vulnerable ports 👀...[/bold red] [bold yellow]Continuing...[/bold yellow]")

    scanner = nmap.PortScanner()
    scan_results = {}
    
    # Show progress spinner during scan
    with Progress(SpinnerColumn(), TextColumn("[yellow]Scanning...")) as progress:
        task = progress.add_task("", total=None)
        # Run nmap scan with version detection (-sV) and OS detection (-O)
        scanner.scan(target, 
                    ",".join(str(port) for port in common_ports.keys()),
                    arguments="-sV -O --version-intensity 5")
        progress.stop()

    # Process scan results for each host
    for host in scanner.all_hosts():
        console.print(f"[bold green]Results for {host}:[/bold green]")
        # Initialize results dictionary for this host
        scan_results[host] = {
            "ports": {},
            "os": {},
            "geolocation": {},
            "vulnerabilities": []
        }
        
        # Get OS detection results
        if 'osmatch' in scanner[host]:
            os_matches = scanner[host]['osmatch']
            if os_matches:
                scan_results[host]['os'] = os_matches[0]
                console.print(f"[bold blue]Detected OS: {os_matches[0]['name']} (Accuracy: {os_matches[0]['accuracy']}%)[/bold blue]")

        # Get geolocation information for the host
        try:
            geo_info = geo_lookup(host)
            if geo_info:
                scan_results[host]['geolocation'] = geo_info
        except Exception as e:
            console.print(f"[bold red]Error getting geolocation: {e}[/bold red]")

        # Check each port in the common ports list
        if 'tcp' in scanner[host]:
            for port in common_ports.keys():
                if port in scanner[host]['tcp']:
                    # Get detailed port information
                    port_info = scanner[host]['tcp'][port]
                    state = port_info['state']
                    service = common_ports[port]
                    product = port_info.get('product', '')
                    version = port_info.get('version', '')
                    
                    # Store port information in results
                    scan_results[host]['ports'][port] = {
                        'state': state,
                        'service': service,
                        'version': version,
                        'product': product
                    }
                    
                    # Handle open ports and check for vulnerabilities
                    if state == "open":
                        version_info = f" ({product} {version})" if product else ""
                        console.print(f"[bold red]⚠️ Port {port} ({service}){version_info} is OPEN! ⚠️[/bold red]")
                        
                        # Check for known vulnerable versions
                        if product and version:
                            vuln_info = check_version_vulnerability(product, version)
                            if vuln_info:
                                console.print(f"[bold red]{vuln_info}[/bold red]")
                                scan_results[host]['vulnerabilities'].append({
                                    'port': port,
                                    'service': service,
                                    'version': version,
                                    'description': vuln_info
                                })
                    else:
                        console.print(f"[bold green]✔️ Port {port} ({service}) is CLOSED! Good job ✔️[/bold green]")

    # Save scan results to file
    save_scan_results(target, scan_results)
    return scan_results

def scan_network_devices():
    """Discovers and scans all devices on your local network.
    
    This function:
    1. Detects your local network range
    2. Discovers all active devices on the network
    3. Displays a table of found devices with their IP and hostname
    4. Optionally performs a detailed port scan on each discovered device
    """
    # Get router IP to determine network range
    router_ip = get_router_ip()
    if router_ip is None:
        console.print("[bold red]Error: Could not detect the router IP.[/bold red]")
        return

    # Calculate network range (e.g., 192.168.1.0/24)
    network_range = router_ip.rsplit('.', 1)[0] + '.0/24'
    console.print(f"[bold yellow]Scanning local network: {network_range} 👨🏻‍💻...[/bold yellow]")

    # Create progress display
    with Progress(SpinnerColumn(), TextColumn("[yellow]Discovering devices...")) as progress:
        task = progress.add_task("", total=None)
        # Perform ping scan to discover devices
        scanner = nmap.PortScanner()
        scanner.scan(hosts=network_range, arguments="-sn")
        progress.stop()

    # Get list of all hosts that responded
    hosts_list = scanner.all_hosts()
    
    if not hosts_list:
        console.print("[bold red]No devices found on the network.[/bold red]")
        return

    # Create a table to display discovered devices
    table = Table(title="🔍 Discovered Devices", title_style="bold cyan")
    table.add_column("IP Address", style="bold white")
    table.add_column("Status", style="bold green")
    table.add_column("Hostname", style="white")

    # Add each discovered device to the table
    for host in hosts_list:
        try:
            hostname = socket.gethostbyaddr(host)[0]
        except:
            hostname = "Unknown"
        
        status = "Up" if scanner[host].state() == "up" else "Down"
        table.add_row(host, status, hostname)

    console.print(table)
    
    # Ask if user wants to scan the discovered devices
    if console.input("\n[bold yellow]Would you like to scan these devices for open ports? (y/n): [/bold yellow]").lower() == 'y':
        for host in hosts_list:
            console.print(f"\n[bold cyan]Scanning {host}...[/bold cyan]")
            scan_target(host)
    else:
        console.print("[bold green]Network discovery completed.[/bold green]")

def scan_current_device():
    """Scans the current device's open ports."""
    # Get current machine's local IP
    local_ip = socket.gethostbyname(socket.gethostname())
    scan_target(local_ip)

def parse_port_range(port_range: str) -> list:
    """Parse port range string into list of ports.
    
    Args:
        port_range (str): Port range string (e.g., '80-443', '80,443,8080')
        
    Returns:
        list: List of port numbers
        
    Raises:
        ValueError: If port range format is invalid
    """
    ports = []
    try:
        # Split multiple ranges by comma
        ranges = port_range.split(',')
        for r in ranges:
            # Handle range format (e.g., '80-443')
            if '-' in r:
                start, end = map(int, r.split('-'))
                # Validate port range
                if start > end:
                    raise ValueError("Start port cannot be greater than end port")
                if start < 1 or end > 65535:
                    raise ValueError("Ports must be between 1 and 65535")
                ports.extend(range(start, end + 1))
            else:
                # Handle single port
                port = int(r)
                if port < 1 or port > 65535:
                    raise ValueError("Ports must be between 1 and 65535")
                ports.append(port)
        return sorted(list(set(ports)))  # Remove duplicates and sort
    except ValueError as e:
        raise ValueError(f"Invalid port range format: {e}")

def scan_target_custom_ports(target: str, port_list: list):
    """Scans a given target IP for specified ports."""
    # [Similar to scan_target() but uses custom port_list instead of common_ports]
    # ... (implementation details similar to scan_target)

def display_scan_options():
    """Display available scanning options in a formatted table."""
    # Create table with title
    table = Table(title="🐆 Choose a Scan Type 🐆", title_style="bold yellow", style="tan")
    table.add_column("Option", style="bold white", justify="center")
    table.add_column("Description", style="bold white")
    
    # Add scan options
    table.add_row("[bold red]1[/bold red]", "Scan a specific target IP (common ports)")
    table.add_row("─" * 15, "─" * 60)
    table.add_row("[bold red]2[/bold red]", "Discover and scan all devices on your local network")
    table.add_row("─" * 15, "─" * 60)
    table.add_row("[bold red]3[/bold red]", "Scan current device")
    table.add_row("─" * 15, "─" * 60)
    table.add_row("[bold red]4[/bold red]", "Scan with custom port range")
    
    console.print(table)

# Main program entry point
if __name__ == "__main__":
    # Display menu and get user choice
    display_scan_options()
    choice = input("Enter your choice: ").strip()

    # Process user's choice
    if choice == "1":
        # Scan specific target
        target_ip = input("Enter target IP or domain: ").strip()
        scan_target(target_ip)

    elif choice == "2":
        # Scan all network devices
        scan_network_devices()

    elif choice == "3":
        # Scan current device
        scan_current_device()

    elif choice == "4":
        # Scan with custom port range
        target_ip = input("Enter target IP or domain: ").strip()
        port_range = input("Enter port range (e.g., '80', '80-443', '80,443,8080'): ").strip()
        try:
            ports = parse_port_range(port_range)
            console.print(f"[bold blue]Scanning ports: {ports}[/bold blue]")
            scan_target_custom_ports(target_ip, ports)
        except ValueError as e:
            console.print(f"[bold red]Error: {e}[/bold red]")
    else:
        # Invalid choice
        console.print("[bold red]❌ Invalid choice. Please select a valid option.[/bold red]")

