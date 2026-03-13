import sys

from scapy.config import conf
from scapy.interfaces import get_working_ifaces
import scanner
import attacks
from utils import is_valid_ip, is_valid_port, is_admin
import time
import argparse
import gui
from rich import print


def run_host_scan(*, ip_range, iface, port_range=None):
    print(f"\nStarting Network Mapper scan on {ip_range}...")
    app = scanner.NetworkScanner(ip_range=ip_range, port_range=port_range, iface=iface)
    app.discover_hosts()
    
    if not app.hosts:
        print("No hosts found.")
        return

    print(f"Discovered {len(app.hosts)} hosts.")
    
    print(f"\n{'IP ADDRESS':<20} {'MAC ADDRESS':<20}")
    print("-" * 40)
    
    for host in app.hosts:
        print(f"{host.ip_address:<20} {host.mac_address:<20}")
        if port_range:
            app.scan_ports(host)
            if host.os:
                print(f"  [OS: {host.os}]")
                
            open_ports = [p for p in host.ports if p.status == "open"]
            if open_ports:
                print(f"\n  {'PORT':<10} {'STATE':<10} {'SERVICE':<15}")
                print(f"  {'-'*35}")
                for p in open_ports:
                    service = p.service if p.service else "unknown"
                    print(f"  {str(p.port_number) + '/tcp':<10} {p.status:<10} {service:<15}")
                print() # Add an empty line after the ports table for readability
            else:
                print("  No open ports found.\n")
            print("-" * 40)
            
    if not port_range:
        print("-" * 40)
                
    print("\nScan completed.")


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
    
    :return: argparse.Namespace object containing the parsed arguments.
    """
    parser = argparse.ArgumentParser(
        description="Network Mapper Tool",
        formatter_class=argparse.RawTextHelpFormatter # Keeps our formatting clean
    )

    # gui - flag - above other args
    parser.add_argument("-g", "--gui", action="store_true",
                        help="Start the application in Graphical Mode.\nIf used, all other arguments are ignored.")

    subparses = parser.add_subparsers(dest="command", help='commands')

    # --- Host Scanning(discovery) ---
    scan_parser = subparses.add_parser("scan", help="Scan for live hosts")

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
    arp_p = subparses.add_parser("ARP", help="Perform ARP poisoning")
    #target and gateway - positonal
    arp_p.add_argument("target", help="Victim IP address")
    arp_p.add_argument("gateway", help="Gateway(router) IP address")

    #iface - flag
    arp_p.add_argument("-i", "--iface", help="Network interface (e.g. eth0).\n"
                            "ADVICE: Manual selection is highly recommended.")


    args = parser.parse_args()

    # handle gui first
    if args.gui:
        return args

    if not args.command:
        parser.print_help()
        sys.exit(1)
    # --- scan ---
    if args.command == "scan":
        if args.port:
            if not is_valid_port(args.range):
                print(f"Error: '{args.range}' is an invalid port format.")
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
            print(f"Error: '{args.target}' is not a valid IPv4 address or CIDR range.")
            sys.exit(1)
        if args.iface:
            # get a list of all active Scapy interface objects
            available_ifaces = get_working_ifaces()

            # try to find a match by Name (GUID) OR desc (friendly name)
            matched_iface = None
            for i in get_working_ifaces():
                if args.iface == i.description or args.iface == i.name:
                    matched_iface = i
                    break

            if matched_iface:
                # override the argument with the actual GUID/Name Scapy needs
                args.iface = matched_iface.name
            else:
                # create a clean list of friendly names to show the user in the error
                friendly_names = [i.description for i in available_ifaces]
                print(f"Error: '{args.iface}' not found.")
                print(f"Available interfaces:\n{'\n'.join(friendly_names)}")
                sys.exit(1)
        else:
            # User didn't provide one; Scapy will try to use 'conf.iface'
            print(f"[!] No interface provided! it is recommended to specify an interface\n"
                  f" Defaulting to: {conf.iface.description}")

    return args


def main():
    #first, check if admin
    if not is_admin():
        print("Error: This script requires administrator/root privileges to run.")
        sys.exit(1)
    args = get_args()
    if args.gui:
        print("Starting GUI...")
        app = gui.NetworkMapperGUI()
        app.mainloop()
    elif args.command == "scan":
        if args.port:
            run_host_scan(ip_range=args.target, iface=args.iface, port_range=args.range)
        else:
            run_host_scan(ip_range=args.target, iface=args.iface)

if __name__ == "__main__":
    main()