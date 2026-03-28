import ipaddress
import os
import ctypes
import subprocess
import re
import platform
import time
from sys import exception
from typing import Optional, Union, Any
from scapy.all import Ether, ARP, srp1, conf


def get_mac_by_ip(target_ip: str, iface: str, retries: int = 3) -> Optional[str]:
    """
    Uses ARP requests to find the MAC address associated with an IP.
    Sends multiple requests and retries to ensure reliability.
    :param target_ip: target's IP address
    :param iface: user's specified/default interface
    :param retries: amount of attempts
    :return: MAC address as a string, or None if not found
    """
    for i in range(retries):
        try:
            # We send a broadcast ARP request
            # sending 2 packets in one go increases the chance of a response
            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ip)

            # srp1 waits for a single response.
            # We use a 1.5s timeout per attempt.
            response = srp1(arp_request, timeout=1.5, iface=iface, verbose=False)

            if response:
                return response.hwsrc

            # If we didn't get a response, wait a tiny bit before the next retry
            if i < retries - 1:
                time.sleep(0.5)
        except Exception as e:
            print(f"Error getting MAC address: {e}")

    return None

def get_gateway(iface: Optional[str] = None) -> Optional[str]:
    """
    finds the IPv4 gateway IP address.
    cross-compatible (Windows/Linux/WSL/macOS).
    :param iface: user's specified/default interface
    :return: gateway IP address as a string, or None if not found
    """
    system = platform.system()

    # 1. Windows: Use PowerShell (Very accurate on Win 10/11)
    if system == 'Windows':
        try:
            # Get the NextHop of the default route with the lowest metric
            cmd = ["powershell", "-Command", "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1).NextHop"]
            output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode().strip()
            if output and is_valid_ip(output) and output != '0.0.0.0':
                return output
        except Exception as e:
            print(f"Error getting gateway IP: {e}")

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
        except Exception as e:
            print(f"Error getting gateway IP: {e}")

    # 2. macOS: Use 'route -n get default'
    elif system == 'Darwin':
        try:
            output = subprocess.check_output("route -n get default", shell=True, stderr=subprocess.DEVNULL).decode()
            match = re.search(r"gateway:\s+([\d\.]+)", output)
            if match:
                return match.group(1)
        except Exception as e:
            print(f"Error getting gateway IP: {e}")

    # 3. Linux / WSL: Use 'ip route'
    else:
        try:
            output = subprocess.check_output("ip route show default", shell=True, stderr=subprocess.DEVNULL).decode()
            match = re.search(r"via\s+([\d\.]+)", output)
            if match:
                return match.group(1)
        except Exception as e:
            print(f"Error getting gateway IP: {e}")

    # 4. Final Fallback: Scapy's internal routing table
    gw = getattr(conf.route, 'gw', None)
    return gw if gw and gw != '0.0.0.0' else None

def broad_os_map(ttl: int) -> str:
    """
    Maps a TTL value to a broad OS category.
    :param ttl: Time To Live value from an IP packet
    :return: String describing the likely OS family
    """
    if 0 < ttl <= 64:
        return "Unix"
    elif 64 < ttl <= 128:
        return "Windows"
    elif 128 < ttl <= 255:
        return "Cisco"
    else:
        return "Unknown"


_vendor_db_cache = None

def get_vendor_by_mac(mac: str) -> tuple:
    """
    looks up vendor and returns a short and long name
    :param mac: MAC address to look up
    :return: Vendor short and long name in a tuple: (short_name, long_name)
    """
    global _vendor_db_cache
    if _vendor_db_cache is None:
        _vendor_db_cache = load_mac_vendor_db()

    short_DB, long_DB = _vendor_db_cache

    if not mac:
        return ("Unknown", "Unknown Vendor")

    # Standardize MAC to uppercase and take prefix in format XX:XX:XX (8 chars)
    mac_prefix = mac.upper()[:8]
    return (short_DB.get(mac_prefix, "Unknown"), long_DB.get(mac_prefix, "Unknown Vendor"))

def load_mac_vendor_db() -> tuple:
    """
    Loads the MAC vendor database using a robust path resolution strategy.
    Checks for resources/vendorDB.txt relative to the package and the CWD.
    :return: Tuple of (short_DB, long_DB)
    """
    short_DB = {}
    long_DB = {}
    current_dir = os.path.dirname(os.path.abspath(__file__))

    # Define potential paths for the vendor database

    path = os.path.join(current_dir, "resources", "vendorDB.txt")

    if not os.path.exists(path):
        return short_DB, long_DB

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # split whitepsace
                parts = line.split()
                if len(parts) >= 2:
                    prefix = parts[0]
                    short_name = parts[1]
                    # rest is long name
                    long_name = " ".join(parts[2:])

                    short_DB[prefix] = short_name
                    long_DB[prefix] = long_name
        return (short_DB, long_DB)
    except Exception as e:
        print(f"Error loading MAC vendor database: {e}")

    return short_DB, long_DB

def is_valid_ip(ip: str) -> bool:
    """
    Validates if a string is a valid IPv4 address or CIDR network.
    :param ip: IP address or CIDR string to validate
    :return: True if valid, False otherwise
    """
    try:
        # interface handles both individual addresses and CIDR networks
        net = ipaddress.ip_network(ip, strict=False)
        if net.version == 6:
            return False
        return True
    except ValueError:
        return False

def is_valid_port(port_str: Union[str, int]) -> bool:
    """
    Validates if a string or integer represents a valid port or port range.
    :param port_str: Port number or range (e.g., "80", "20-80")
    :return: True if valid, False otherwise
    """
    try:
        # Split by dash to handle ranges, then convert to ints
        ports = [int(p) for p in str(port_str).split('-')]

        if not (1 <= len(ports) <= 2):
            return False

        return all(0 <= p <= 65535 for p in ports) and (ports[0] <= ports[-1])
    except ValueError:
        return False

def get_friendly_iface_name(scapy_iface_name: str) -> str:
    """
    translates a Scapy interface GUID to a Windows Interface Alias
    :param scapy_iface_name: The name or GUID of the interface used by Scapy
    :return: friendly interface name
    """
    if os.name != 'nt':
        return scapy_iface_name

    try:
        # Use PowerShell to get the mapping between GUID and Alias
        # This is the most reliable way to get the name netsh/powershell commands want.
        cmd = ["powershell", "-Command", f"Get-NetAdapter | Where-Object {{$_.InterfaceGuid -eq '{scapy_iface_name}' -or $_.DeviceID -eq '{scapy_iface_name}'}} | Select-Object -ExpandProperty Name"]

        # If the input was already a friendly name, try to validate it
        if "{" not in scapy_iface_name:
             cmd = ["powershell", "-Command", f"Get-NetAdapter | Where-Object {{$_.Name -eq '{scapy_iface_name}'}} | Select-Object -ExpandProperty Name"]

        output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode().strip()
        if output:
            return output

        # Fallback to Scapy's list if PowerShell fails
        from scapy.arch.windows import get_windows_if_list
        for iface in get_windows_if_list():
            if iface['name'] == scapy_iface_name:
                return iface['description']
    except Exception as e:
        print(f"Error getting interface alias: {e}")
    return scapy_iface_name

def set_static_arp(iface_name: str, ip: str, mac: str) -> None:
    """
    sets a static ARP entry to protect the local machine from self-poisoning.
    :param iface_name: user's specified/default interface
    :param ip: gateway's IP address
    :param mac: gateway's MAC address
    :return: None
    """
    if os.name == 'nt':
        friendly_name = get_friendly_iface_name(iface_name)
        try:
            # We use PowerShell to set a 'Permanent' neighbor entry
            # First try to create it, then try to update it if it already exists
            create_cmd = ["powershell", "-Command", f"New-NetNeighbor -InterfaceAlias '{friendly_name}' -IPAddress '{ip}' -LinkLayerAddress '{mac}' -State Permanent -ErrorAction SilentlyContinue"]
            subprocess.run(create_cmd, capture_output=True)

            update_cmd = ["powershell", "-Command", f"Set-NetNeighbor -InterfaceAlias '{friendly_name}' -IPAddress '{ip}' -LinkLayerAddress '{mac}' -State Permanent -ErrorAction SilentlyContinue"]
            subprocess.run(update_cmd, capture_output=True)
        except Exception as e:
            print(f"Error setting network interface alias: {e}")
    else:
        # Linux/Unix equivalent
        try:
            subprocess.run(["ip", "neigh", "replace", ip, "lladdr", mac, "dev", iface_name, "nud", "permanent"],
                           capture_output=True, check=False)
        except Exception as e:
            print(f"Error setting static ARP entry: {e}")

def remove_static_arp(iface_name: str, ip: str) -> None:
    """
    removes a static ARP entry, reverting it to dynamic.
    :param iface_name: user's specified/default interface
    :param ip: gateway's IP address
    :return: None
    """
    if os.name == 'nt':
        friendly_name = get_friendly_iface_name(iface_name)
        try:
            # Remove the neighbor entry so it reverts to standard dynamic discovery
            cmd = ["powershell", "-Command", f"Remove-NetNeighbor -InterfaceAlias '{friendly_name}' -IPAddress '{ip}' -Confirm:$false -ErrorAction SilentlyContinue"]
            subprocess.run(cmd, capture_output=True)
        except Exception as e:
            print(f"Error removing static ARP entry: {e}")
    else:
        # Linux/Unix equivalent
        try:
            subprocess.run(["ip", "neigh", "del", ip, "dev", iface_name],
                           capture_output=True, check=False)
        except Exception as e:
            print(f"Error removing static ARP entry: {e}")

def is_admin() -> bool:
    """
    Checks if the script is running with administrative/root privileges.
    :return: True if running as admin/root, False otherwise
    """
    try:
        # windows
        if os.name == 'nt':
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        # Unix
        else:
            return os.getuid() == 0
    except AttributeError:
        return False
