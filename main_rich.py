import sys

from scapy.config import conf
from scapy.interfaces import get_working_ifaces
from scapy.layers.l2 import getmacbyip
import models
import scanner
import attacks
from utils import is_valid_ip, is_valid_port, is_admin, get_target_mac
import time
import argparse
from rich_argparse import RawTextRichHelpFormatter
import gui

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.theme import Theme
from rich.rule import Rule

custom_theme = Theme({
    "info": "#88c0d0",
    "info_bold": "bold #88c0d0",
    "success": "#a3be8c",
    "success_bold": "bold #a3be8c",
    "warning": "bold #ebcb8b",
    "error": "bold #bf616a",
    "muted": "#d8dee9",
    "muted_light": "#e5e9f0",
    "highlight": "bold #b48ead",
    "border": "#81a1c1"
})

console = Console(theme=custom_theme)

# Optionally configure rich_argparse to use our custom styles (must use hex/standard colors directly)
RawTextRichHelpFormatter.styles["argparse.prog"] = "bold #88c0d0"
RawTextRichHelpFormatter.styles["argparse.groups"] = "#88c0d0"
RawTextRichHelpFormatter.styles["argparse.args"] = "#a3be8c"
RawTextRichHelpFormatter.styles["argparse.metavar"] = "bold #b48ead"
RawTextRichHelpFormatter.styles["argparse.help"] = "#e5e9f0"

def print_error_panel(msg):
    console.print()
    console.print(Panel(
        f"[muted]{msg}[/]",
        title="[error]Error[/]",
        border_style="#bf616a",
        expand=False
    ))

def print_warning_panel(msg, title="Warning"):
    console.print()
    console.print(Panel(
        f"[muted]{msg}[/]",
        title=f"[warning]{title}[/]",
        border_style="warning",
        expand=False
    ))


def resolve_iface(iface_arg):
    """
    Validate and normalize a user-supplied interface argument.
    - If an interface is supplied, try to match it by description or name.
      On success, set scapy's default iface and return the normalized name.
      On failure, print a helpful error + available interfaces and exit.
    - If no interface is supplied, warn and fall back to scapy's default.
    """
    if iface_arg:
        available_ifaces = get_working_ifaces()
        matched_iface = None
        for i in available_ifaces:
            if iface_arg == i.description or iface_arg == i.name:
                matched_iface = i
                break

        if matched_iface:
            conf.iface = matched_iface.name
            return matched_iface.name

        friendly_names = [i.description for i in available_ifaces]
        print_error_panel(f"'{iface_arg}' not found.")
        print_warning_panel(
            f"Available interfaces:\n[muted_light]{'\n'.join(friendly_names)}[/]",
            title="Interfaces"
        )
        sys.exit(1)

    # No iface provided: fall back to scapy's default interface
    print_warning_panel(
        f"No interface provided! It is recommended to specify an interface.\n"
        f"Defaulting to: [info_bold]{conf.iface.description}[/]",
        title="Missing Interface"
    )

    # Ensure we return a usable interface name for downstream code
    if hasattr(conf.iface, "name"):
        return conf.iface.name
    return str(conf.iface)

def run_host_scan(*, ip_range, iface, port_range=None):
    console.print()
    console.print(Rule(title=f"[info_bold]Starting Network Mapper scan on {ip_range}...[/]", style="border"))
    app = scanner.NetworkScanner(ip_range=ip_range, port_range=port_range, iface=iface)
    app.discover_hosts()
    
    if not app.hosts:
        console.print("[muted]No hosts found.[/]")
        console.print(Rule(style="border"))
        console.print()
        return

    console.print(f"[success]Discovered {len(app.hosts)} hosts.[/]\n")
    
    for host in app.hosts:
        renderables = []
        if port_range:
            app.scan_ports(host)
            if host.os:
                renderables.append(f"[highlight]OS:[/highlight] [muted_light]{host.os}[/]")
            else:
                renderables.append(f"[highlight]OS:[/highlight] [muted_light]Unknown[/]")
                
            open_ports = [p for p in host.ports if p.status == "open"]
            if open_ports:
                table = Table(box=None, padding=(0, 3))
                table.add_column("PORT", style="info")
                table.add_column("STATE")
                table.add_column("SERVICE", style="muted")
                
                for p in open_ports:
                    service = p.service if p.service else "unknown"
                    table.add_row(f"{str(p.port_number)}/tcp", "🟢 [success_bold]open[/]", service)
                renderables.append(table)
            else:
                renderables.append("[muted]⚪ No open ports found.[/]")
        else:
            renderables.append("[muted]⚪ Port scan not requested.[/]")
            
        group = Group(*renderables)
        panel = Panel(
            group,
            title=f"[info_bold]{host.ip_address}[/] - [muted_light]{host.mac_address}[/]",
            title_align="center",
            border_style="border",
            expand=False
        )
        console.print(panel)
        console.print()
                
    console.print(Rule(title="[info_bold]Scan complete.[/]", style="border"))
    console.print()



def arp_spoof(*, target_ip, gateway_ip, iface):
    console.print()
    console.print(Rule(title="[info_bold]Starting ARP Spoofing Attack...[/]", style="border"))
    
    console.print("[muted]Resolving MAC addresses...[/]")
    target_mac = get_target_mac(target_ip, iface)
    gateway_mac = get_target_mac(gateway_ip, iface)
    
    if not target_mac:
        print_error_panel(f"Could not resolve MAC address for target {target_ip}")
        return
    if not gateway_mac:
        print_error_panel(f"Could not resolve MAC address for gateway {gateway_ip}")
        return
        
    target = models.Host(ip_address=target_ip, mac_address=target_mac)
    gateway = models.Host(ip_address=gateway_ip, mac_address=gateway_mac)
    
    renderables = [
        f"[highlight]Target:[/highlight]  [info]{target_ip}[/] [muted_light]->[/] {target_mac}",
        f"[highlight]Gateway:[/highlight] [info]{gateway_ip}[/] [muted_light]->[/] {gateway_mac}"
    ]
    
    group = Group(*renderables)
    panel = Panel(
        group,
        title="[warning]Poisoning Targets[/]",
        title_align="center",
        border_style="warning",
        expand=False
    )
    console.print(panel)
    
    arp_poison = attacks.ArpPoisoning(target=target, gateway=gateway, iface=iface)
    arp_poison.start()
    
    console.print("\n[success_bold]Attack is running![/] [muted]Traffic is being intercepted and forwarded.[/]")
    
    ws_filter = f"ip.addr == {target_ip}"
    console.print(f"[info]💡 Tip:[/] [muted_light]Open Wireshark on [info_bold]{iface}[/] and use this filter to see the target's traffic:[/]")
    console.print(f"       [highlight]{ws_filter}[/]")
    
    try:
        console.input("\n[info_bold]Press ENTER to stop the attack...[/]\n")
    except KeyboardInterrupt:
        console.print()
    finally:
        console.print("[warning]Stopping attack and restoring ARP tables...[/]")
        arp_poison.stop()
        console.print(Rule(title="[info_bold]Attack Stopped[/]", style="border"))
        console.print()

def run_cli(ip_range, port_range, iface):
    """
    runs the CLI version of the network mapper
    :param ip_range: IP range to scan. can be a single ip
    :param port_range: Port range to scan. default is 1-1024. can be a single port
    :param iface: iface to perform scan on. if None, Scapy will use default
    :return:
    """
    print("--- Network Mapper CLI ---")
    print(f"Starting host discovery on {ip_range}...")
    app = scanner.NetworkScanner(ip_range, port_range)
    discovered_hosts = app.run_scan(iface)
    
    if not discovered_hosts:
        print("No hosts found.")
        return

    for i, host in enumerate(discovered_hosts):
        print(f"[{i}] Host: {host.ip_address} ({host.mac_address})")

    # Example of manual port scan for a specific host
    choice = 0 # Let's pick the first one for demonstration
    target_host = discovered_hosts[choice]
    print(f"\nScanning ports for {target_host.ip_address}...")
    app.scan_ports(target_host, iface)
    
    print(f"OS: {target_host.os}")
    for port in target_host.ports:
        if port.status == "open":
            print(f"  Port {port.port_number} is open")

    # TEST ARP Poisoning between first two hosts if available
    if len(discovered_hosts) >= 2:
        print(f"\nStarting test ARP poisoning: {discovered_hosts[1].ip_address} <-> {discovered_hosts[0].ip_address}")
        arppoison = attacks.ArpPoisoning(discovered_hosts[1], discovered_hosts[0], iface)
        arppoison.start()
        time.sleep(5)
        arppoison.stop()

class RichArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        """Override default error method to print inside a Rich panel."""
        import re
        usage = self.format_usage()
        # Collapse newlines and extra spaces in usage to prevent breaking the Panel frame
        usage_clean = re.sub(r'\s+', ' ', usage).strip()
        
        err_msg = f"[muted]{message}[/]\n\n[muted_light]{usage_clean}[/]"
        
        console.print()
        console.print(Panel(
            err_msg,
            title="[error]Argument Error[/]",
            border_style="#bf616a",
            expand=False
        ))
        sys.exit(2)

    def print_help(self, file=None):
        """Override default print_help to wrap the rich-argparse output in a Panel."""
        from rich.text import Text
        help_text = self.format_help()
        
        console.print()
        console.print(Panel(
            Text.from_ansi(help_text) if "\x1b" in help_text else help_text,
            title="[info_bold]Help & Usage[/]",
            border_style="#81a1c1",
            expand=False
        ))

def get_args():
    """
    Parses and validates command-line arguments using argparse.
    
    Accessing the arguments from the returned object:
    - args.gui: (bool) True if graphical mode is requested (-g/--gui).
    - args.command: (str) The selected subcommand ('scan' or 'ARP').
    
    If args.command == 'scan':
    - args.target: (str) The target IPv4 address or CIDR range.
    - args.iface: (str) The network interface to use.
    - args.port: (bool) True if port scanning is enabled (-p/--port).
    - args.range: (int | list) The port(s) to scan. Will be an int for a single port, or a list of ints for a range.
    
    If args.command == 'ARP':
    - args.target: (str) The victim IP address.
    - args.gateway: (str) The gateway (router) IP address.
    - args.iface: (str) The network interface to use.

    If args.command == 'DOS':
    - args.ifacae (str) The network interface to use
    
    :return: argparse.Namespace object containing the parsed arguments.
    """
    parser = RichArgumentParser(
        description="Network Mapper Tool",
        formatter_class=RawTextRichHelpFormatter # Keeps our formatting clean
    )

    # gui - flag - above other args
    parser.add_argument("-g", "--gui", action="store_true",
                        help="Start the application in Graphical Mode.\n"
                        "If used, all other arguments are ignored.")

    subparses = parser.add_subparsers(dest="command", help='commands')

    # --- Host Scanning(discovery) ---
    scan_parser = subparses.add_parser(
        "scan", 
        help="Scan for live hosts",
        formatter_class=RawTextRichHelpFormatter
    )

    # target - positional
    scan_parser.add_argument("target", type=str, help="The target IPv4 address or CIDR range (e.g., 192.168.1.1 or 192.168.1.0/24).")
    #iface - flag
    scan_parser.add_argument("-i", "--iface", help="Network interface (e.g. eth0).\n"
                            "ADVICE: Manual selection is highly recommended.")
    #ports switch (true/false)
    scan_parser.add_argument("-p", "--port", action="store_true", help="Enable port scanning")
    #port range
    scan_parser.add_argument("-r", "--range", default="1-1024", type=str,  help="Port range to scan. Can be a single port or a range.\ne.g 8 or 1-1024")

    # --- Arp Spoofing ---
    arp_p = subparses.add_parser(
        "ARP", 
        help="Perform ARP poisoning",
        formatter_class=RawTextRichHelpFormatter,
        aliases=["arp"]
    )
    #target and gateway - positonal
    arp_p.add_argument("target", help="Victim IP address")
    arp_p.add_argument("gateway", help="Gateway(router) IP address")

    #iface - flag
    arp_p.add_argument("-i", "--iface", help="Network interface (e.g. eth0).\n"
                            "ADVICE: Manual selection is highly recommended.")

    # --- Dos Attack ---
    dos_p = subparses.add_parser(
        "DOS",
        help="Perform DoS attack",
        formatter_class = RawTextRichHelpFormatter
        aliases=["dos"]
    )
    
    #iface - flag
    dos_p.add_argument("-i", "--iface", help="Network interface (e.g. eth0).\n"
                            "ADVICE: Manual selection is highly recommended.")

    args = parser.parse_args()

    # handle gui first
    if args.gui:
        return args

    if not args.command:
        parser.print_help()
        sys.exit(1)

    args.command = args.command.upper() # normalize

    # --- scan ---
    if args.command == "SCAN":
        if args.port:
            if not is_valid_port(args.range):
                print_error_panel(f"'{args.range}' is an invalid port format.")
                sys.exit(1)
            else:
                if "-" in args.range:
                    start, end = args.range.split("-")
                    # convert port range to list
                    args.range = list(range(int(start), int(end) + 1))
                else:
                    # handle single port
                    args.range = int(args.range)
        if not is_valid_ip(args.target):
            print_error_panel(f"'{args.target}' is not a valid IPv4 address or CIDR range.")
            sys.exit(1)
        args.iface = resolve_iface(args.iface)

    # --- ARP ---
    elif args.command == "ARP":
        if not is_valid_ip(args.target):
            print_error_panel(f"Target '{args.target}' is not a valid IPv4 address.")
            sys.exit(1)
        if not is_valid_ip(args.gateway):
            print_error_panel(f"Gateway '{args.gateway}' is not a valid IPv4 address.")
            sys.exit(1)
        args.iface = resolve_iface(args.iface)

    return args


def main():
    #first, check if admin
    if not is_admin():
        print_error_panel("This script requires administrator/root privileges to run.")
        sys.exit(1)
    args = get_args()
    if args.gui:
        print("Starting GUI...")
        app = gui.NetworkMapperGUI()
        app.mainloop()
    elif args.command == "SCAN":
        if args.port:
            run_host_scan(ip_range=args.target, iface=args.iface, port_range=args.range)
        else:
            run_host_scan(ip_range=args.target, iface=args.iface)
    elif args.command == "ARP":
        arp_spoof(target_ip=args.target, gateway_ip=args.gateway, iface=args.iface)

if __name__ == "__main__":
    main()