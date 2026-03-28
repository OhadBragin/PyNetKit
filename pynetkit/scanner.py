from typing import List, Optional, Dict, Any, Union
from scapy.all import srp, sr1, time, DNS, DNSQR, ICMP
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
import logging

# Suppress scapy runtime warnings (e.g. "MAC address to reach destination not found")
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from . import models
from .utils import broad_os_map, get_vendor_by_mac


class NetworkScanner:
    """
    Provides functionality to scan a network for hosts and ports.
    """

    def __init__(self, *, ip_range: str, port_range: Optional[Union[str, int, List[int]]] = None, iface: str) -> None:
        """
        Initializes the NetworkScanner.
        :param ip_range: The IP range to scan (e.g., "192.168.1.0/24")
        :param port_range: The port or range of ports to scan
        :param iface: The network interface to use
        :return: None
        """
        self.ip_range: str = ip_range
        self.port_range: Optional[Union[str, int, List[int]]] = port_range
        self.iface: str = iface
        self.hosts: List[models.Host] = []

    def discover_hosts(self) -> None:
        """
        Discovers hosts in the specified IP range using ARP requests.
        Only works for local networks.
        :return: None
        """
        pkts_arp = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self.ip_range)
        ans_arp, _ = srp(pkts_arp, timeout=1, iface=self.iface, verbose=False)
        for _, rcv in ans_arp:
            host = models.Host(ip_address=rcv[ARP].psrc, mac_address=rcv[ARP].hwsrc)
            host.short_vendor, host.long_vendor = get_vendor_by_mac(host.mac_address)
            self.hosts.append(host)

    def scan_ports(self, host_obj: models.Host) -> None:
        """
        Scans the specified host for open ports in the specified
        port range using TCP SYN scan, and tries to guess
        the OS using ttl. It then updates the host's ports
        list with <models.Port> objects.
        :param host_obj: The Host object to scan
        :return: None
        """
        known_ports: Dict[int, str] = {
            20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
            53: "domain", 80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
            139: "netbios-ssn", 143: "imap", 443: "https", 445: "microsoft-ds",
            993: "imaps", 995: "pop3s", 1723: "pptp", 3306: "mysql",
            3389: "ms-wbt-server", 5432: "postgresql", 5900: "vnc",
            8080: "http-proxy", 8443: "https-alt"
        }

        # TCP Scan
        pkts_tcp = Ether(dst=host_obj.mac_address) / IP(dst=host_obj.ip_address) / TCP(dport=self.port_range, flags="S")
        ans_tcp, unans_tcp = srp(pkts_tcp, timeout=1, iface=self.iface, verbose=False)
        for snd, rsp in ans_tcp:
            if rsp.haslayer(TCP):
                port_num = rsp[TCP].sport
                service = known_ports.get(port_num, "unknown")
                if rsp[TCP].flags == "SA":  # SYN-ACK
                    port = models.Port(port_number=port_num, status="open", service=service, proto="tcp")
                    host_obj.add_port(port)
                    host_obj.os = broad_os_map(rsp[IP].ttl)
                elif rsp[TCP].flags == "RA":  # RST-ACK
                    port = models.Port(port_number=port_num, status="closed", service=service, proto="tcp")
                    host_obj.add_port(port)
                    host_obj.os = broad_os_map(rsp[IP].ttl)
            # Non-TCP responses (e.g. ICMP unreachable)
            elif rsp.haslayer(ICMP):
                port_num = snd[TCP].dport
                service = known_ports.get(port_num, "unknown")
                port = models.Port(port_number=port_num, status="filtered", service=service, proto="tcp")
                host_obj.add_port(port)

        # ports that got no response at all are filtered
        for snd in unans_tcp:
            port_num = snd[TCP].dport
            service = known_ports.get(port_num, "unknown")
            port = models.Port(port_number=port_num, status="filtered", service=service, proto="tcp")
            host_obj.add_port(port)

        # UDP Scan (Layer 2)
        pkts_udp = Ether(dst=host_obj.mac_address) / IP(dst=host_obj.ip_address) / UDP(dport=self.port_range)
        ans_udp, unans_udp = srp(pkts_udp, timeout=1, iface=self.iface, verbose=False)
        
        for snd, rsp in ans_udp:
            if rsp.haslayer(UDP):
                port_num = rsp[UDP].sport
                service = known_ports.get(port_num, "unknown")
                port = models.Port(port_number=port_num, status="open", service=service, proto="udp")
                host_obj.add_port(port)
            elif rsp.haslayer(ICMP):
                port_num = snd[UDP].dport
                service = known_ports.get(port_num, "unknown")
                port = models.Port(port_number=port_num, status="closed", service=service, proto="udp")
                host_obj.add_port(port)

        for snd in unans_udp:
            port_num = snd[UDP].dport
            service = known_ports.get(port_num, "unknown")
            port = models.Port(port_number=port_num, status="open|filtered", service=service, proto="udp")
            host_obj.add_port(port)


class TraceScanner:
    """
    Provides functionality to trace the network path to a target.
    """

    def __init__(self, *, target_ip: str, max_hops: int) -> None:
        """
        Initializes the TraceScanner.
        :param target_ip: The destination IP address
        :param max_hops: Maximum number of hops to trace
        :return: None
        """
        self.target_ip: str = target_ip
        self.max_hops: int = max_hops
        self.path: List[Dict[str, Any]] = []

    @staticmethod
    def resolve_hostname(hostname: str) -> Optional[str]:
        """
        translates hostname to an IP address using an A type DNS query.
        :param hostname: The hostname to resolve
        :return: IP address of the host or None if resolution fails
        """
        #We ask google's DNS server
        pkt = IP(dst="8.8.8.8") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=hostname, qtype="A"))
        rsp = sr1(pkt, timeout=2, verbose=False)
        if rsp and rsp.haslayer(DNS) and rsp[DNS].ancount > 0:
            for i in range(rsp[DNS].ancount):
                if rsp[DNS].an[i].type == 1:
                    rdata = rsp[DNS].an[i].rdata
                    return rdata.decode() if isinstance(rdata, bytes) else rdata
        return None
    def craft_packet(self, ttl: int) -> IP:
        """
        Crafts an ICMP Echo Request packet with the specified TTL
        to be sent to the target IP for traceroute purposes.
        :param ttl: The Time To Live value for the packet
        :return: A Scapy IP packet object
        """
        pkt = IP(dst=self.target_ip, ttl=ttl) / ICMP()
        return pkt

    def run_trace(self) -> None:
        """
        Executes the traceroute by sending packets with increasing TTL values.
        :return: None
        """
        for ttl in range(1, self.max_hops + 1):
            pkt = self.craft_packet(ttl)
            start_time = time.time()
            ans = sr1(pkt, timeout=1, verbose=False)
            end_time = time.time()
            rtt = round((end_time - start_time) * 1000, 2)
            
            if ans is None:
                self.path.append({"hop": ttl, "ip": "*", "time": "*", "target_reached": False})
                continue
            else:
                target_reached = (ans.src == self.target_ip or (ans.haslayer(ICMP) and ans[ICMP].type in [0, 3]))
                self.path.append({"hop": ttl, "ip": ans.src, "time": f"{rtt} ms", "target_reached": target_reached})
                if target_reached:
                    break

    def start(self) -> None:
        """
        Starts the traceroute process.
        :return: None
        """
        self.run_trace()
