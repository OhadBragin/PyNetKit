import pytest
import sys
import os

# Ensure the root directory is in sys.path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from models import Host, Port

def test_port_init():
    port = Port(80, "Open", "HTTP", "TCP")
    assert port.port_number == 80
    assert port.status == "Open"
    assert port.service == "HTTP"
    assert port.proto == "TCP"

def test_host_init():
    host = Host("192.168.1.1", "AA:BB:CC:DD:EE:FF")
    assert host.ip_address == "192.168.1.1"
    assert host.mac_address == "AA:BB:CC:DD:EE:FF"
    assert host.ports == []
    assert host.os is None

def test_host_add_port():
    host = Host("192.168.1.1")
    port = Port(80, "Open")
    host.add_port(port)
    assert len(host.ports) == 1
    assert host.ports[0] == port
