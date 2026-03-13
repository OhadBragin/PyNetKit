from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether

import models
from utils import broad_os_map
class NetworkScanner:
    def __init__(self, *, ip_range, port_range=None, iface):
        self.ip_range = ip_range
        self.port_range = port_range
        self.iface = iface
        self.hosts = []

    def discover_hosts(self):
        """
        Uses ARP request to discover active hosts in the specified IP range
        and updates the hosts list with <models.Host> objects representing
        the discovered hosts
        :return: None
        """
        pkts = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self.ip_range)
        ans, unans = srp(pkts, timeout=1, iface=self.iface, verbose=False)
        for snd, rcv in ans:
            host = models.Host(ip_address=rcv[ARP].psrc, mac_address=rcv[ARP].hwsrc)
            self.hosts.append(host)


    def scan_ports(self, host_obj):
        """
        Scans the specified host for open ports in the specified
        port range using TCP SYN scan, and tries to guess
        the OS using ttl. It then updates the host's ports
        list with <models.Port> objects, representing the
        open ports and their services
        :param host_obj:
        :return: None
        """
        known_ports = {
            20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
            53: "domain", 80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
            139: "netbios-ssn", 143: "imap", 443: "https", 445: "microsoft-ds",
            993: "imaps", 995: "pop3s", 1723: "pptp", 3306: "mysql",
            3389: "ms-wbt-server", 5432: "postgresql", 5900: "vnc",
            8080: "http-proxy", 8443: "https-alt"
        }

        pkts = Ether(dst=host_obj.mac_address) / IP(dst=host_obj.ip_address) / TCP(dport=self.port_range, flags="S")
        ans, unans = srp(pkts, timeout=1, iface=self.iface, verbose=False)
        for snd, rsp in ans:
            if rsp.haslayer(TCP):
                port_num = rsp[TCP].sport
                service = known_ports.get(port_num, "unknown")
                if rsp[TCP].flags == "SA": #SYN-ACK - port open
                    port = models.Port(port_number=port_num, status="open", service=service)
                    host_obj.add_port(port)
                    host_obj.os = broad_os_map(rsp[IP].ttl)
                elif rsp[TCP].flags == "RA": #RST-ACK - port closed
                    port = models.Port(port_number=port_num, status="closed", service=service)
                    host_obj.add_port(port)
                    host_obj.os = broad_os_map(rsp[IP].ttl)
            else: #No TCP layer - could be filtered or no response
                port_num = snd[TCP].dport
                service = known_ports.get(port_num, "unknown")
                port = models.Port(port_number=port_num, status="filtered", service=service)
                host_obj.add_port(port)
        #UDP
        pkts = Ether(dst=host_obj.mac_address) / IP(dst=host_obj.ip_address) / UDP(dport=self.port_range)
        ans, unans = srp(pkts, timeout=1, iface=self.iface, verbose=False)
        for snd, rsp in ans:
            if rsp is None: #open or filtered
                port_num = snd[UDP].dport
                service = known_ports.get(port_num, "unknown")
                port = models.Port(port_number=port_num, status="open/filtered", service=service)
                host_obj.add_port(port)
            elif rsp.haslayer(UDP): #is open
                port_num = rsp[UDP].sport
                service = known_ports.get(port_num, "unknown")
                port = models.Port(port_number=port_num, status="open", service=service)
                host_obj.add_port(port)
                host_obj.os = broad_os_map(rsp[IP].ttl)


