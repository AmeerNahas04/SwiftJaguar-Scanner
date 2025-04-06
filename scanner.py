import nmap
import socket
import os
import platform
import requests
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box

# Initialize rich console
console = Console()

# ASCII Jaguar Logo
jaguar_logo = """ 
       🐆        /\_/\      🐆
 🐆             ( o.o )              🐆
          🐆     > ^ <     🐆
  🐆             🐆                🐆
"""

# Display Title Banner
title = "SwiftJaguar's Swifty Vulnerability Scanner"
console.print(Panel.fit(f"[bold yellow]{jaguar_logo}[/bold yellow]\n[bold red]{title}[/bold red]", title="SwiftJaguar",))

# Dictionary of common ports and services
common_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NetBIOS",
    143: "IMAP",
    445: "SMB",
    3389: "RDP",
    8080: "HTTP Proxy"
}

def get_router_ip():
    """Returns the default gateway IP (router)."""
    system_platform = platform.system()

    if system_platform == "Windows":
        output = os.popen('ipconfig').read()
        for line in output.splitlines():
            if "Default Gateway" in line:
                parts = line.split(":")
                if len(parts) > 1:
                    return parts[1].strip()
    else:
        output = os.popen('ip route' if system_platform == "Linux" else 'netstat -rn').read()
        for line in output.splitlines():
            if "default" in line:
                return line.split()[2]
    return None

def geo_lookup(ip):
    """Fetches and displays geolocation info for a public IP."""
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        data = response.json()

        if data["status"] == "success":
            content = (
                f"🌐 [bold yellow]Geolocation Info[/bold yellow]\n"
                f"📍 [bold green]City:[/bold green] {data['city']}\n"
                f"🗺️ [bold green]Region:[/bold green] {data['regionName']}\n"
                f"🇨🇺 [bold green]Country:[/bold green] {data['country']}\n"
                f"🌐 [bold green]ISP:[/bold green] {data['isp']}\n"
                f"🏢 [bold green]Org:[/bold green] {data['org']}"
            )
            console.print(Panel(content, title=f"📡 {ip}", title_align="center", width=60, box=box.ROUNDED, padding=(1, 2)))
        else:
            console.print("[bold red]Geolocation lookup failed.[/bold red]")
    except Exception as e:
        console.print(f"[bold red]Error fetching geolocation: {e}[/bold red]")

def scan_target(target):
    """Scans a specific IP for open common ports."""
    console.print(f"[bold red]Scanning {target}...[/bold red]")

    scanner = nmap.PortScanner()

    with Progress(SpinnerColumn(), TextColumn("[yellow]Scanning...")) as progress:
        task = progress.add_task("", total=None)
        scanner.scan(target, ",".join(str(p) for p in common_ports.keys()))
        progress.stop()

    for host in scanner.all_hosts():
        console.print(f"[bold green]Results for {host}:[/bold green]")
        geo_lookup(host)

        if 'tcp' in scanner[host]:
            for port in common_ports.keys():
                if port in scanner[host]['tcp']:
                    state = scanner[host]['tcp'][port]['state']
                    service = common_ports[port]
                    if state == "open":
                        console.print(f"[bold red]⚠️ Port {port} ({service}) is OPEN![/bold red]")
                    else:
                        console.print(f"[bold green]✔️ Port {port} ({service}) is CLOSED.[/bold green]")

def scan_current_device():
    """Scans your own PC's local IP."""
    local_ip = socket.gethostbyname(socket.gethostname())
    scan_target(local_ip)

def scan_router():
    """Scans your router (default gateway) for open ports."""
    router_ip = get_router_ip()
    if router_ip:
        scan_target(router_ip)
    else:
        console.print("[bold red]Could not find your router's IP.[/bold red]")

def display_scan_options():
    """Displays the scan menu."""
    table = Table(title="🐆 Choose a Scan Type 🐆", title_style="bold yellow", style="tan")
    table.add_column("Option", style="bold white", justify="center")
    table.add_column("Description", style="bold white")

    table.add_row("[bold red]1[/bold red]", "Scan a specific target IP")
    table.add_row("─" * 15, "─" * 60)
    table.add_row("[bold red]2[/bold red]", "Scan your router (gateway IP)")
    table.add_row("─" * 15, "─" * 60)
    table.add_row("[bold red]3[/bold red]", "Scan current PC")
    console.print(table)

# === Main Execution ===
if __name__ == "__main__":
    display_scan_options()
    choice = input("Enter your choice: ").strip()

    if choice == "1":
        target_ip = input("Enter target IP or domain: ").strip()
        scan_target(target_ip)
    elif choice == "2":
        scan_router()
    elif choice == "3":
        scan_current_device()
    else:
        console.print("[bold red]❌ Invalid choice. Try again![/bold red]")
