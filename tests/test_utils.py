import pytest
import sys
import os

# Ensure the root directory is in sys.path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from pynetkit.utils import is_valid_ip, is_valid_port, broad_os_map, get_vendor_by_mac

from unittest.mock import patch

def test_get_vendor_by_mac():
    mock_db = (
        {"00:0C:29": "VMware", "B8:27:EB": "Raspberry"},
        {"00:0C:29": "VMware, Inc.", "B8:27:EB": "Raspberry Pi Foundation"}
    )
    with patch("pynetkit.utils.load_mac_vendor_db", return_value=mock_db):
        # Reset cache for test
        import pynetkit.utils
        pynetkit.utils._vendor_db_cache = None
        
        assert get_vendor_by_mac("00:0c:29:ab:cd:ef") == ("VMware", "VMware, Inc.")
        assert get_vendor_by_mac("b8:27:eb:11:22:33") == ("Raspberry", "Raspberry Pi Foundation")
        assert get_vendor_by_mac("00:00:00:00:00:00") == ("Unknown", "Unknown Vendor")
        assert get_vendor_by_mac("") == ("Unknown", "Unknown Vendor")

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
    assert broad_os_map(64) == "Unix"
    assert broad_os_map(128) == "Windows"
    assert broad_os_map(255) == "Cisco"
    assert broad_os_map(0) == "Unknown"
    assert broad_os_map(300) == "Unknown"
