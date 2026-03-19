import pytest
import sys
import os

# Ensure the root directory is in sys.path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from pynetkit.utils import is_valid_ip, is_valid_port, broad_os_map

def test_is_valid_ip():
    assert is_valid_ip("192.168.1.1") == True
    assert is_valid_ip("10.0.0.0/24") == True
    assert is_valid_ip("256.256.256.256") == False
    assert is_valid_ip("invalid-ip") == False
    assert is_valid_ip("::1") == False  # is_valid_ip checks for IPv6 and returns False

def test_is_valid_port():
    assert is_valid_port(80) == True
    assert is_valid_port("80") == True
    assert is_valid_port("20-80") == True
    assert is_valid_port("80-20") == False # ports[0] <= ports[-1]
    assert is_valid_port(65536) == False
    assert is_valid_port("1-2-3") == False
    assert is_valid_port("abc") == False

def test_broad_os_map():
    assert broad_os_map(64) == "Unix-based (Linux/Unix/MacOS)"
    assert broad_os_map(128) == "Windows"
    assert broad_os_map(255) == "Cisco/Network Device"
    assert broad_os_map(0) == "Unknown/Spoofed"
    assert broad_os_map(300) == "Unknown/Spoofed"
