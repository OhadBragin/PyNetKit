class Port:
    def __init__(self, port_number, status, service=None):
        self.port_number = port_number
        self.status = status
        self.service = service

class Host:
    def __init__(self, ip_address=None, mac_address=None):
        self.ip_address = ip_address
        self.mac_address = mac_address
        self.ports = []
        self.os = None

    def add_port(self, port_obj):
        self.ports.append(port_obj)