import nmap  # This is the scanning tool
import socket  # Provides low-level networking capabilities
import os  # For executing system commands
import platform  # To check the platform
import json # Saves/views scan results
from rich.console import Console  # Allows the cool style in terminal
from rich.panel import Panel  # Creates fancy terminal boxes
from rich.table import Table  # Creates structured terminal tables
from rich.progress import Progress, SpinnerColumn, TextColumn  # Adds a loading spinner

# Check if nmap is installed
try:
    scanner = nmap.PortScanner()
except nmap.PortScannerError:
    print("Error: Nmap is not installed or not found. Please install it first with pip install python-nmap.")
    exit(1)

# Below is the cute interface
console = Console()
jaguar_logo = """ 
       🐆        /\_/\      🐆
 🐆             ( o.o )              🐆
          🐆     > ^ <     🐆
  🐆             🐆                🐆
"""

# Title of the Scanner
title = "SwiftJaguar's Swifty Vulnerability Scanner"

# Displays the banner
console.print(Panel.fit(f"[bold yellow]{jaguar_logo}[/bold yellow]\n[bold red]{title}[/bold red]", title="SwiftJaguar"))

# Common Ports that shouldn't be open
common_ports = {
    21: "FTP (File Transfer Protocol)",
    22: "SSH (Secure Shell)",
    23: "Telnet (Unsecure Remote Login)",
    25: "SMTP (Mail Server)",
    53: "DNS (Domain Name System)",
    80: "HTTP (Web Traffic)",
    110: "POP3 (Email Protocol)",
    139: "NetBIOS (Windows File Sharing)",
    143: "IMAP (Email Protocol)",
    445: "SMB (Windows File Sharing)",
    3389: "RDP (Remote Desktop Protocol)",
    8080: "HTTP Proxy"
}

# Getting the Local Network 
def get_local_network():
    """Detects the local network range (e.g., 192.168.1.0/24)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        network_range = ".".join(local_ip.split(".")[:3]) + ".0/24"
        return network_range
    except Exception as e:
        return f"Error: {e}"

# Gets the router IP
def get_router_ip():
    """Get the router's IP address (default gateway)."""
    system_platform = platform.system()

    if system_platform == "Windows":
        # Use ipconfig to get the default gateway on Windows
        gateway = os.popen('ipconfig').read()
        
        # Find the line with "Default Gateway" and extract the IP
        lines = gateway.splitlines()
        for i in range(len(lines)):
            if "Default Gateway" in lines[i]:
                try:
                    # Get the gateway IP which should be after the colon
                    router_ip = lines[i].split(":")[1].strip()
                    if router_ip:
                        return router_ip
                except IndexError:
                    continue
    else:
        # Use netstat or ip route to get the default gateway on Linux/Mac
        gateway = os.popen('netstat -rn' if system_platform == "Darwin" else 'ip route').read()
        for line in gateway.splitlines():
            if "default" in line:
                router_ip = line.split()[2]
                return router_ip

    return None  # If the default gateway cannot be found

# Scanning a Single Target
def scan_target(target):
    """Scans a given target IP for common vulnerable ports."""
    console.print(f"[bold red]Scanning {target} for vulnerable ports 👀...[/bold red] [bold yellow]Continuing...[/bold yellow]")

    scanner = nmap.PortScanner()
    with Progress(SpinnerColumn(), TextColumn("[yellow]Scanning...")) as progress:
        task = progress.add_task("", total=None)
        scanner.scan(target, ",".join(str(port) for port in common_ports.keys()))
        progress.stop()

    for host in scanner.all_hosts():
        console.print(f"[bold green]Results for {host}:[/bold green]")
        if 'tcp' in scanner[host]:
            for port in common_ports.keys():
                if port in scanner[host]['tcp']:
                    state = scanner[host]['tcp'][port]['state']
                    service = common_ports[port]
                    if state == "open":
                        console.print(f"[bold red]⚠️ Port {port} ({service}) is OPEN! ⚠️[/bold red]")
                    else:
                        console.print(f"[bold green]✔️ Port {port} ({service}) is CLOSED! Good job ✔️[/bold green]")
                        

# Scanning the Whole Network
def scan_local_network():
    """Scans all devices on the local network for common vulnerable ports."""
    router_ip = get_router_ip()
    if router_ip is None:
        console.print("[bold red]Error: Could not detect the router IP.[/bold red]")
        return

    network_range = router_ip.rsplit('.', 1)[0] + '.0/24'
    console.print(f"[bold yellow]Scanning local network: {network_range} 👨🏻‍💻...[/bold yellow]")

    scanner = nmap.PortScanner()
    scanner.scan(hosts=network_range, arguments="-sn")

    for host in scanner.all_hosts():
        console.print(f"\n[bold green]🖥️ Device Found: {host}[/bold green]")
        scan_target(host)

# Scanning the current device
def scan_current_device():

    local_ip = socket.gethostbyname(socket.gethostname())
    scan_target(local_ip)


# Function to display scan options
def display_scan_options():
    table = Table(title="🐆 Choose a Scan Type 🐆", title_style="bold yellow", style="tan")
    table.add_column("Option", style="bold white", justify="center")
    table.add_column("Description", style="bold white")
    
    table.add_row("[bold red]1[/bold red]", "Scan a specific target IP")
    table.add_row("─" * 15, "─" * 60)
    table.add_row("[bold red]2[/bold red]", "Scan the open/closed ports on your router/connected network")
    table.add_row("─" * 15, "─" * 60)
    table.add_row("[bold red]3[/bold red]", "Scan current device")
    
    console.print(table)

# Choosing what to scan
if __name__ == "__main__":
    display_scan_options()
    choice = input("Enter your choice: ").strip()

    if choice == "1":
        target_ip = input("Enter target IP or domain: ").strip()
        scan_target(target_ip)

    elif choice == "2":
        scan_local_network()

    elif choice == "3":
        scan_current_device()

    else:
        console.print("[bold red]❌ Cmon, you have two choices... for now :)[/bold red]")

