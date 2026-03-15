import ipaddress
import os
import ctypes
import subprocess
import re
from scapy.all import Ether, ARP, srp1, conf

def get_mac_by_ip(target_ip, iface):
    """
    Uses ARP requests to find the MAC address
    associated with a given IP address on the local network.
    """
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ip)
    response = srp1(arp_request, timeout=2, iface=iface, verbose=False)
    if response:
        return response.hwsrc
    return None


def get_gateway(normalized_iface=None):
    """
    Finds the IPv4 gateway IP address.
    Resilient and cross-compatible (Windows/Linux/WSL).
    """
    # 1. Windows: Use PowerShell (Very accurate on Win 10/11)
    if os.name == 'nt':
        try:
            # Get the NextHop of the default route with the lowest metric
            cmd = ["powershell", "-Command", "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1).NextHop"]
            output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode().strip()
            if output and is_valid_ip(output) and output != '0.0.0.0':
                return output
        except:
            pass

        # Windows Fallback: Parse 'route print'
        try:
            output = subprocess.check_output("route print 0.0.0.0", shell=True).decode()
            for line in output.splitlines():
                if line.strip().startswith("0.0.0.0"):
                    parts = line.split()
                    if len(parts) >= 3:
                        gw = parts[2] # Gateway is the 3rd column
                        if is_valid_ip(gw) and gw != '0.0.0.0':
                            return gw
        except:
            pass

    # 2. Linux / WSL: Use 'ip route'
    else:
        try:
            output = subprocess.check_output("ip route show default", shell=True, stderr=subprocess.DEVNULL).decode()
            match = re.search(r"via\s+([\d\.]+)", output)
            if match:
                return match.group(1)
        except:
            pass

    # 3. Final Fallback: Scapy's internal routing table
    gw = getattr(conf.route, 'gw', None)
    return gw if gw and gw != '0.0.0.0' else None

def broad_os_map(ttl):
    if 0 < ttl <= 64:
        return "Unix-based (Linux/Unix/MacOS)"
    elif 64 < ttl <= 128:
        return "Windows"
    elif 128 < ttl <= 255:
        return "Cisco/Network Device"
    else:
        return "Unknown/Spoofed"


def is_valid_ip(ip):
    try:
        # interface handles both individual addresses and CIDR networks
        net = ipaddress.ip_network(ip, strict=False)
        if net.version == 6:
            return False
        return True
    except ValueError:
        return False


def is_valid_port(port_str):
    try:
        # Split by dash to handle ranges, then convert to ints
        ports = [int(p) for p in str(port_str).split('-')]

        if not (1 <= len(ports) <= 2):
            return False

        return all(0 <= p <= 65535 for p in ports) and (ports[0] <= ports[-1])
    except ValueError:
        return False

def is_admin():
    try:
        # windows
        if os.name == 'nt':
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        # Unix
        else:
            return os.getuid() == 0
    except AttributeError:
        return False