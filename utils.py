import ipaddress
import os
import ctypes
from scapy.all import Ether, ARP, srp1

def get_target_mac(target_ip, iface):
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ip)
    response = srp1(arp_request, timeout=2, iface=iface, verbose=False)
    if response:
        return response.hwsrc
    return None

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