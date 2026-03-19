import unittest
from unittest.mock import MagicMock, patch
from scanner import NetworkScanner
from models import Host, Port
from scapy.layers.l2 import ARP
from scapy.layers.inet import IP, TCP, UDP

class TestNetworkScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = NetworkScanner(ip_range="192.168.1.0/24", port_range=[80, 443], iface="eth0")

    @patch("scanner.srp")
    def test_discover_hosts(self, mock_srp):
        # Mocking ARP response
        mock_rcv = MagicMock()
        mock_rcv.haslayer.return_value = True
        mock_rcv[ARP].psrc = "192.168.1.5"
        mock_rcv[ARP].hwsrc = "00:11:22:33:44:55"
        
        mock_ans = [(MagicMock(), mock_rcv)]
        mock_srp.return_value = (mock_ans, [])

        self.scanner.discover_hosts()

        self.assertEqual(len(self.scanner.hosts), 1)
        self.assertEqual(self.scanner.hosts[0].ip_address, "192.168.1.5")
        self.assertEqual(self.scanner.hosts[0].mac_address, "00:11:22:33:44:55")

    @patch("scanner.srp")
    @patch("scanner.broad_os_map")
    def test_scan_ports(self, mock_os_map, mock_srp):
        host = Host(ip_address="192.168.1.5", mac_address="00:11:22:33:44:55")
        mock_os_map.return_value = "Linux"

        # Mocking TCP response (SYN-ACK for port 80)
        mock_tcp_snd = MagicMock()
        mock_tcp_snd[TCP].dport = 80
        
        mock_tcp_rsp = MagicMock()
        mock_tcp_rsp.haslayer.side_effect = lambda layer: layer == TCP
        mock_tcp_rsp[TCP].sport = 80
        mock_tcp_rsp[TCP].flags = "SA"
        mock_tcp_rsp[IP].ttl = 64
        
        # Mocking UDP response (UDP for port 443)
        mock_udp_snd = MagicMock()
        mock_udp_snd[UDP].dport = 443
        
        mock_udp_rsp = MagicMock()
        mock_udp_rsp.haslayer.side_effect = lambda layer: layer == UDP
        mock_udp_rsp[UDP].sport = 443

        # We need to simulate TWO calls to srp: one for TCP and one for UDP
        mock_srp.side_effect = [
            ([(mock_tcp_snd, mock_tcp_rsp)], []), # TCP Scan result
            ([(mock_udp_snd, mock_udp_rsp)], [])  # UDP Scan result
        ]

        self.scanner.scan_ports(host)

        self.assertEqual(len(host.ports), 2)
        
        # Check TCP port 80
        port80 = next(p for p in host.ports if p.port_number == 80)
        self.assertEqual(port80.status, "open")
        self.assertEqual(port80.proto, "tcp")
        
        # Check UDP port 443
        port443 = next(p for p in host.ports if p.port_number == 443)
        self.assertEqual(port443.status, "open")
        self.assertEqual(port443.proto, "udp")
        
        self.assertEqual(host.os, "Linux")

if __name__ == "__main__":
    unittest.main()
