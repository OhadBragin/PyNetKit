from typing import List, Optional


class Port:
    """
    Represents a network port and its associated metadata.
    """

    def __init__(self, port_number: int, status: str, service: Optional[str] = None, proto: Optional[str] = None) -> None:
        """
        Initializes a Port object.
        :param port_number: The port number
        :param status: The status of the port (e.g., "Open", "Closed")
        :param service: Optional name of the service running on the port
        :param proto: Optional protocol (e.g., "TCP", "UDP")
        :return: None
        """
        self.port_number: int = port_number
        self.proto: Optional[str] = proto
        self.status: str = status
        self.service: Optional[str] = service


class Host:
    """
    Represents a network host and its discovered attributes.
    """

    def __init__(self, ip_address: Optional[str] = None, mac_address: Optional[str] = None) -> None:
        """
        Initializes a Host object.
        :param ip_address: Optional IP address of the host
        :param mac_address: Optional MAC address of the host
        :return: None
        """
        self.ip_address: Optional[str] = ip_address
        self.mac_address: Optional[str] = mac_address
        self.short_vendor: Optional[str] = None
        self.long_vendor: Optional[str] = None
        self.ports: List[Port] = []
        self.os: Optional[str] = None

    def add_port(self, port_obj: Port) -> None:
        """
        Adds a Port object to the host's list of discovered ports.
        :param port_obj: The Port instance to add
        :return: None
        """
        self.ports.append(port_obj)
