import sys

from scapy.config import conf
from scapy.interfaces import get_working_ifaces
from scapy.layers.l2 import getmacbyip
import models
import scanner
import attacks
from utils import is_valid_ip, is_valid_port, is_admin, get_mac_by_ip, get_gateway
import time
import argparse
from rich_argparse import RawTextRichHelpFormatter


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
      On success, return the normalized name.
      On failure, print a helpful error + available interfaces and exit.
    - If no interface is supplied, warn and return scapy's default.
    """
    if iface_arg:
        available_ifaces = get_working_ifaces()
        matched_iface = None
        for i in available_ifaces:
            if iface_arg == i.description or iface_arg == i.name:
                matched_iface = i
                break

        if matched_iface:
            return matched_iface.name

        friendly_names = [i.description for i in available_ifaces]
        interfaces_str = '\n'.join(friendly_names)
        print_error_panel(f"'{iface_arg}' not found.")
        print_warning_panel(
            f"Available interfaces:\n[muted_light]{interfaces_str}[/]",
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
    
    with console.status("[muted]Discovering hosts (ARP)...[/]"):
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

def arp_spoof(*, target_ip, iface, do_save=False, dns_domain=None, dns_ip=None):
    console.print()
    console.print(Rule(title="[info_bold]Starting ARP Spoofing Attack...[/]", style="border"))
    
    # Auto-resolve gateway
    gateway_ip = get_gateway(iface)
    if not gateway_ip:
        print_error_panel(f"Could not automatically resolve gateway for interface {iface}")
        sys.exit(1)
        
    console.print(f"[muted]Resolved gateway IP: {gateway_ip}[/]")
    console.print("[muted]Resolving MAC addresses...[/]")
    target_mac = get_mac_by_ip(target_ip, iface)
    gateway_mac = get_mac_by_ip(gateway_ip, iface)
    
    if not target_mac:
        print_error_panel(f"Could not resolve MAC address for target {target_ip}")
        sys.exit(1)
    if not gateway_mac:
        print_error_panel(f"Could not resolve MAC address for gateway {gateway_ip}")
        sys.exit(1)
        
    target = models.Host(ip_address=target_ip, mac_address=target_mac)
    gateway = models.Host(ip_address=gateway_ip, mac_address=gateway_mac)
    
    renderables = [
        f"[highlight]Target:[/highlight]  [info]{target_ip}[/] [muted_light]->[/] {target_mac}",
        f"[highlight]Gateway:[/highlight] [info]{gateway_ip}[/] [muted_light]->[/] {gateway_mac}"
    ]

    if dns_domain and dns_ip:
        renderables.append(f"[highlight]DNS Spoof:[/highlight] [info]{dns_domain}[/] [muted_light]->[/] [success]{dns_ip}[/]")
    
    group = Group(*renderables)
    panel = Panel(
        group,
        title="[warning]Poisoning Targets[/]",
        title_align="center",
        border_style="warning",
        expand=False
    )
    console.print(panel)
    
    arp_poison = attacks.ArpPoisoning(
        target=target, 
        gateway=gateway, 
        iface=iface, 
        do_save=do_save,
        original_domain=dns_domain,
        spoofed_ip=dns_ip
    )
    arp_poison.start()
    
    console.print("\n[success_bold]Attack is running![/] [muted]Traffic is being intercepted and forwarded.[/]")
    if do_save:
        console.print(f"[success]Saving packets to:[/] [info_bold]{arp_poison.pcap_filename}[/]")
    
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

def run_single_dos(*, target_ip, iface):
    console.print()
    console.print(Rule(title="[info_bold]Starting Single Target DoS Attack...[/]", style="border"))
    
    # Auto-resolve gateway
    gateway_ip = get_gateway(iface)
    if not gateway_ip:
        print_error_panel(f"Could not automatically resolve gateway for interface {iface}")
        sys.exit(1)
        
    console.print(f"[muted]Resolved gateway IP: {gateway_ip}[/]")
    console.print("[muted]Resolving MAC addresses...[/]")
    
    target_mac = get_mac_by_ip(target_ip, iface)
    if not target_mac:
        print_error_panel(f"Could not resolve MAC address for target {target_ip}")
        sys.exit(1)
        
    gateway_mac = get_mac_by_ip(gateway_ip, iface)
    if not gateway_mac:
        print_error_panel(f"Could not resolve MAC address for gateway {gateway_ip}. Aborting to ensure restoration safety.")
        sys.exit(1)
        
    target = models.Host(ip_address=target_ip, mac_address=target_mac)
    dos_attack = attacks.SingleTargetDos(
        target=target, 
        gateway_ip=gateway_ip, 
        gateway_mac=gateway_mac,
        iface=iface
    )
    
    console.print(f"[highlight]Target:[/highlight] [info]{target_ip}[/] [muted_light]->[/] {target_mac}")
    console.print(f"[highlight]Gateway:[/highlight] [info]{gateway_ip}[/] [muted_light]->[/] {gateway_mac}")
    
    dos_attack.start()
    console.print("\n[success_bold]Attack is running![/] [muted]Poisoning target to disrupt connection.[/]")
    
    try:
        console.input("\n[info_bold]Press ENTER to stop the attack...[/]\n")
    except KeyboardInterrupt:
        console.print()
    finally:
        console.print("[warning]Stopping DoS attack and restoring target ARP table...[/]")
        dos_attack.stop()
        console.print(Rule(title="[info_bold]Attack Stopped[/]", style="border"))
        console.print()

def run_dhcp_dos(*, iface):
    console.print()
    console.print(Rule(title="[info_bold]Starting DHCP DoS Attack...[/]", style="border"))
    dos_attack = attacks.DHCPStarvation(iface=iface)
    dos_attack.start()
    console.print("\n[success_bold]Attack is running![/] [muted]Flooding network with DHCP Discover packets.[/]")
    
    try:
        console.input("\n[info_bold]Press ENTER to stop the attack...[/]\n")
    except KeyboardInterrupt:
        console.print()
    finally:
        console.print("[warning]Stopping DoS attack...[/]")
        dos_attack.stop()
        console.print(Rule(title="[info_bold]Attack Stopped[/]", style="border"))
        console.print()

def trace_scan(*, target, max_hops=30):
    target_ip = target
    if not is_valid_ip(target):
        with console.status(f"[muted]Resolving hostname '{target}'...[/]"):
            resolved_ip = scanner.TraceScanner.resolve_hostname(target)
        if not resolved_ip:
            print_error_panel(f"Could not resolve hostname: '{target}'.\nPlease provide a valid IPv4 address or domain.")
            sys.exit(1)
        console.print(f"🌍 [success]Resolved '{target}' to {resolved_ip}[/]")
        target_ip = resolved_ip

    console.print()
    console.print(Rule(title=f"[info_bold]Starting Trace Route to {target}...[/]", style="border"))
    
    app = scanner.TraceScanner(target_ip=target_ip, max_hops=max_hops)
    
    with console.status(f"[success_bold]Tracing route to {target_ip} (max hops: {max_hops})..."):
        app.start()
        
    if not app.path:
        console.print("[muted]No hops found or target unreachable.[/]")
        console.print(Rule(style="border"))
        console.print()
        return

    table = Table(box=None, padding=(0, 3))
    table.add_column("HOP", style="info", justify="right")
    table.add_column("TIME", style="muted", justify="right")
    table.add_column("IP ADDRESS")

    for hop_data in app.path:
        hop_num = str(hop_data["hop"])
        ip = hop_data["ip"]
        rtt = hop_data["time"]
        table.add_row(hop_num, rtt, f"[success_bold]{ip}[/]" if ip == target_ip else ip)

    panel = Panel(
        table,
        title=f"[info_bold]Trace Route Complete[/] - {len(app.path)} hops",
        title_align="center",
        border_style="border",
        expand=False
    )
    console.print(panel)
    
    if len(app.path) > 0 and app.path[-1]["ip"] != target_ip:
        console.print(f"[warning]Target {target_ip} was not reached within {max_hops} hops.[/]")
    else:
        console.print(f"[success]Target {target_ip} reached in {len(app.path)} hops.[/]")
        
    console.print(Rule(style="border"))
    console.print()

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
    - args.iface (str) The network interface to use
    
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
    #target - positonal
    arp_p.add_argument("target", help="Victim IP address")

    #iface - flag
    arp_p.add_argument("-i", "--iface", help="Network interface (e.g. eth0).\n"
                            "ADVICE: Manual selection is highly recommended.")
    #save - flag
    arp_p.add_argument("-s", "--save", action="store_true", help="Save intercepted packets to a pcap file")
    
    # DNS Spoofing arguments
    arp_p.add_argument("--dns-domain", help="Domain name to spoof (e.g. google.com)")
    arp_p.add_argument("--dns-ip", help="IP address to return for the spoofed domain")

    # --- Dos Attack ---
    dos_p = subparses.add_parser(
        "DOS",
        help="Perform DoS attack",
        formatter_class = RawTextRichHelpFormatter,
        aliases=["dos"]
    )
    
    dos_subparsers = dos_p.add_subparsers(dest="dos_type", help="Type of DoS attack")
    
    # Single Target DoS
    single_dos = dos_subparsers.add_parser("single", help="DoS a single target")
    single_dos.add_argument("target", help="Target IP address")
    single_dos.add_argument("-i", "--iface", help="Network interface")

    # Network DoS (DHCP Starvation)
    network_dos = dos_subparsers.add_parser("network", help="DoS the entire network (DHCP Starvation)")
    network_dos.add_argument("-i", "--iface", help="Network interface")

    # --- Trace Route ---
    trace_p = subparses.add_parser(
        "TRACE",
        help="Perform a trace route to a target",
        formatter_class=RawTextRichHelpFormatter,
        aliases=["trace"]
    )
    trace_p.add_argument("target", help="Target IP address or domain")
    trace_p.add_argument("-m", "--max-hops", type=int, default=30, help="Maximum number of hops (default: 30)")

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
        
        # Validate DNS spoofing arguments
        if args.dns_domain or args.dns_ip:
            if not (args.dns_domain and args.dns_ip):
                print_error_panel("Both --dns-domain and --dns-ip must be provided for DNS spoofing.")
                sys.exit(1)
            if not is_valid_ip(args.dns_ip):
                print_error_panel(f"DNS spoof IP '{args.dns_ip}' is not a valid IPv4 address.")
                sys.exit(1)
        
        args.iface = resolve_iface(args.iface)

    # --- DOS ---
    elif args.command == "DOS":
        if not args.dos_type:
            print_error_panel("Please specify a DoS type: 'single' or 'network'.")
            sys.exit(1)
        
        if args.dos_type == "single":
            if not is_valid_ip(args.target):
                print_error_panel(f"Target '{args.target}' is not a valid IPv4 address.")
                sys.exit(1)
            args.iface = resolve_iface(args.iface)
        elif args.dos_type == "network":
            args.iface = resolve_iface(args.iface)

    # --- TRACE ---
    elif args.command == "TRACE":
        pass

    return args

def main():
    #first, check if admin
    if not is_admin():
        print_error_panel("This script requires administrator/root privileges to run.")
        sys.exit(1)
    args = get_args()
    if args.gui:
        import gui
        print("Starting GUI...")
        app = gui.NetworkMapperGUI()
        app.mainloop()
    elif args.command == "SCAN":
        if args.port:
            run_host_scan(ip_range=args.target, iface=args.iface, port_range=args.range)
        else:
            run_host_scan(ip_range=args.target, iface=args.iface)
    elif args.command == "ARP":
        arp_spoof(
            target_ip=args.target, 
            iface=args.iface, 
            do_save=args.save,
            dns_domain=args.dns_domain,
            dns_ip=args.dns_ip
        )
    elif args.command == "DOS":
        if args.dos_type == "single":
            run_single_dos(target_ip=args.target, iface=args.iface)
        elif args.dos_type == "network":
            run_dhcp_dos(iface=args.iface)
    elif args.command == "TRACE":
        trace_scan(target=args.target, max_hops=args.max_hops)

if __name__ == "__main__":
    main()