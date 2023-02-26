import struct

from _socket import gethostbyname_ex, gethostname
from typing import List

from utils import NETWORK


class DHCPServerConfiguration(object):
    dhcp_offer_after_seconds = 0
    dhcp_acknowledge_after_seconds = 0
    length_of_transaction = 40

    bind_address = '0.0.0.0'
    network = '192.168.0.0'
    broadcast_address = '255.255.255.255'
    subnet_mask = '255.255.255.0'
    domain_name_server = ["8.8.8.8", "8.8.4.4", "1.1.1.1"]  # list of ips
    # 1 day is 86400
    login_wait_time = 120  # 2 minutes
    login_refresh_time = 60*60  # 1 hour
    # Gateway config
    captive_gateway = ['192.168.0.4']
    internet_gateway = ['192.168.0.1']

    router = None
    ip_address_lease_time = 0

    host_file = 'hosts.csv'

    debug = print

    def load(self, file):
        with open(file) as f:
            exec(f.read(), self.__dict__)

    def adjust_if_this_computer_is_a_router(self):
        host_ip_addresses = get_host_ip_addresses()
        for ip in reversed(host_ip_addresses):
            if ip.split('.')[-1] == '1':
                self.router = [ip]
                self.domain_name_server = [ip]
                self.network = '.'.join(ip.split('.')[:-1] + ['0'])
                self.broadcast_address = '.'.join(ip.split('.')[:-1] + ['255'])
                # self.ip_forwarding_enabled = True
                # self.non_local_source_routing_enabled = True
                # self.perform_mask_discovery = True

    def all_ip_addresses(self, offset=5):
        """
        :param offset: Number of ips to skip in the beginning
        :return: A generator to get consecutive ips in given network
        """
        ips = ip_addresses(self.network, self.subnet_mask)
        for i in range(offset):
            next(ips)
        return ips

    def network_filter(self):
        return NETWORK(self.network, self.subnet_mask)


def get_host_ip_addresses() -> List[str]:
    """
    :return: List of ip of all interfaces of current host
    """
    return gethostbyname_ex(gethostname())[2]


def ip_addresses(network: str, subnet_mask: str):
    """
    :param network: The network ip
    :param subnet_mask: The subnet mask
    :return: A generator to get consecutive ips in given network
    """
    import socket
    subnet_mask = struct.unpack('>I', socket.inet_aton(subnet_mask))[0]
    network = struct.unpack('>I', socket.inet_aton(network))[0]
    network = network & subnet_mask
    start = network + 1
    end = (network | (~subnet_mask & 0xffffffff))
    return (socket.inet_ntoa(struct.pack('>I', i)) for i in range(start, end))
