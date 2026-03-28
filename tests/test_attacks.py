import time
import sys
import os
from unittest.mock import MagicMock, patch, mock_open

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from pynetkit.models import Host
from pynetkit.attacks import ArpPoisoning, DHCPStarvation, SingleTargetDos


def _make_host(ip="192.168.1.50", mac="aa:bb:cc:dd:ee:ff"):
    return Host(ip_address=ip, mac_address=mac)


def _make_arp_attack(**kwargs):
    with patch("pynetkit.attacks.get_if_hwaddr", return_value="de:ad:c0:de:00:01"):
        return ArpPoisoning(
            target=_make_host("192.168.1.50", "aa:bb:cc:dd:ee:ff"),
            gateway=_make_host("192.168.1.1", "11:22:33:44:55:66"),
            iface="eth0",
            do_save=False,
            **kwargs,
        )


def _make_dos():
    with patch("pynetkit.attacks.get_if_hwaddr", return_value="de:ad:c0:de:00:02"):
        return SingleTargetDos(
            target=_make_host("192.168.1.50", "aa:bb:cc:dd:ee:ff"),
            gateway_ip="192.168.1.1",
            gateway_mac="11:22:33:44:55:66",
            iface="eth0",
        )


# --- ArpPoisoning ---

@patch("pynetkit.attacks.sendp")
def test_poison_tables_sends_two_packets(mock_sendp):
    attack = _make_arp_attack()
    attack.poison_tables()
    assert mock_sendp.call_count == 2


@patch("pynetkit.attacks.sendp")
def test_restore_tables_sends_two_packets(mock_sendp):
    attack = _make_arp_attack()
    attack.restore_tables()
    assert mock_sendp.call_count == 2


@patch("pynetkit.attacks.sendp")
def test_stop_calls_restore_tables(mock_sendp):
    attack = _make_arp_attack()
    attack.is_running = False
    with patch.object(attack, "restore_tables") as mock_restore:
        attack.stop()
    mock_restore.assert_called_once()


@patch("pynetkit.attacks.sniff")
def test_start_sniffing_exits_when_stopped(mock_sniff):
    attack = _make_arp_attack()
    attack.is_running = False
    attack.start_sniffing()
    mock_sniff.assert_not_called()


@patch("pynetkit.attacks.sniff")
def test_start_sniffing_uses_timeout_and_store(mock_sniff):
    attack = _make_arp_attack()

    def stop_after_first(**kw):
        attack.is_running = False

    mock_sniff.side_effect = stop_after_first
    attack.is_running = True
    attack.start_sniffing()

    mock_sniff.assert_called_once()
    _, kwargs = mock_sniff.call_args
    assert kwargs.get("timeout") == 1
    assert kwargs.get("store") == False


def test_check_new_domain_records_each_domain_once():
    attack = _make_arp_attack()
    attack.visited_domains_file = "/tmp/_pynetkit_test_domains.txt"

    with patch("builtins.open", mock_open()) as mocked_file:
        attack.check_new_domain("example.com")
        attack.check_new_domain("example.com")  # duplicate — must not re-write
        attack.check_new_domain("other.com")

    assert "example.com" in attack.visited_domains
    assert "other.com" in attack.visited_domains

    written = [c.args[0] for c in mocked_file().write.call_args_list]
    assert written.count("example.com\n") == 1
    assert written.count("other.com\n") == 1


def test_send_spoofed_dns_returns_false_when_not_configured():
    attack = _make_arp_attack()
    pkt = MagicMock()
    assert attack.send_spoofed_dns(pkt) == False


@patch("pynetkit.attacks.sendp")
def test_forward_packet_ignores_non_ip(mock_sendp):
    attack = _make_arp_attack()
    pkt = MagicMock()
    pkt.haslayer.return_value = False
    attack.forward_packet(pkt)
    mock_sendp.assert_not_called()


# --- DHCPStarvation ---

@patch("pynetkit.attacks.conf")
@patch("pynetkit.attacks.sendp")
def test_dhcp_start_and_stop(mock_sendp, mock_conf):
    attack = DHCPStarvation(iface="eth0")
    attack.start()
    time.sleep(0.05)
    attack.stop()

    assert attack.is_running == False
    assert mock_sendp.call_count > 0


@patch("pynetkit.attacks.conf")
@patch("pynetkit.attacks.sendp")
def test_dhcp_randomizes_mac_each_iteration(mock_sendp, mock_conf):
    sent_srcs = []

    def capture(pkt, **kw):
        frame = pkt if not isinstance(pkt, list) else pkt[0]
        try:
            sent_srcs.append(frame.src)
        except Exception:
            pass

    mock_sendp.side_effect = capture

    attack = DHCPStarvation(iface="eth0")
    attack.start()
    time.sleep(0.1)
    attack.stop()

    if len(sent_srcs) >= 2:
        assert len(set(sent_srcs)) > 1


# --- SingleTargetDos ---

def test_dos_dummy_macs_are_distinct():
    dos = _make_dos()
    assert dos.dummy_target_mac != dos.dummy_gateway_mac


@patch("pynetkit.attacks.sendp")
def test_dos_send_poison_packets_sends_one_call_with_two_frames(mock_sendp):
    dos = _make_dos()
    dos.send_poison_packets()
    mock_sendp.assert_called_once()
    assert len(mock_sendp.call_args.args[0]) == 2


@patch("pynetkit.attacks.sendp")
def test_dos_restore_tables_sends_count_3(mock_sendp):
    dos = _make_dos()
    dos.restore_tables()
    mock_sendp.assert_called_once()
    assert mock_sendp.call_args.kwargs.get("count") == 3


@patch("pynetkit.attacks.sendp")
def test_dos_stop_calls_restore_tables(mock_sendp):
    dos = _make_dos()
    dos.is_running = False
    with patch.object(dos, "restore_tables") as mock_restore:
        dos.stop()
    mock_restore.assert_called_once()


@patch("pynetkit.attacks.sendp")
def test_dos_start_stop_lifecycle(mock_sendp):
    dos = _make_dos()
    dos.start()
    time.sleep(0.05)
    dos.stop()

    assert dos.is_running == False
    assert mock_sendp.call_count > 0