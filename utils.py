import ipaddress
import os
import ctypes
import subprocess
import re
from scapy.all import Ether, ARP, srp1, conf

def get_mac_by_ip(target_ip, iface, retries=3):
    """
    Uses ARP requests to find the MAC address associated with an IP.
    Sends multiple requests and retries to ensure reliability.
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
        except:
            pass
            
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

def get_friendly_iface_name(scapy_iface_name):
    """
    Translates a Scapy interface GUID to a Windows Interface Alias 
    (the 'Friendly Name' like 'Ethernet 2').
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
    except:
        pass
    return scapy_iface_name

def set_static_arp(iface_name, ip, mac):
    """Sets a static ARP entry to protect the local machine from self-poisoning."""
    if os.name == 'nt':
        friendly_name = get_friendly_iface_name(iface_name)
        try:
            # We use PowerShell to set a 'Permanent' neighbor entry
            # First try to create it, then try to update it if it already exists
            create_cmd = ["powershell", "-Command", f"New-NetNeighbor -InterfaceAlias '{friendly_name}' -IPAddress '{ip}' -LinkLayerAddress '{mac}' -State Permanent -ErrorAction SilentlyContinue"]
            subprocess.run(create_cmd, capture_output=True)
            
            update_cmd = ["powershell", "-Command", f"Set-NetNeighbor -InterfaceAlias '{friendly_name}' -IPAddress '{ip}' -LinkLayerAddress '{mac}' -State Permanent -ErrorAction SilentlyContinue"]
            subprocess.run(update_cmd, capture_output=True)
        except:
            pass
    else:
        # Linux/Unix equivalent
        try:
            subprocess.run(["ip", "neigh", "replace", ip, "lladdr", mac, "dev", iface_name, "nud", "permanent"],
                           capture_output=True, check=False)
        except:
            pass

def remove_static_arp(iface_name, ip):
    """Removes a static ARP entry, reverting it to dynamic."""
    if os.name == 'nt':
        friendly_name = get_friendly_iface_name(iface_name)
        try:
            # Remove the neighbor entry so it reverts to standard dynamic discovery
            cmd = ["powershell", "-Command", f"Remove-NetNeighbor -InterfaceAlias '{friendly_name}' -IPAddress '{ip}' -Confirm:$false -ErrorAction SilentlyContinue"]
            subprocess.run(cmd, capture_output=True)
        except:
            pass
    else:
        # Linux/Unix equivalent
        try:
            subprocess.run(["ip", "neigh", "del", ip, "dev", iface_name],
                           capture_output=True, check=False)
        except:
            pass

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