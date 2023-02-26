import collections
import threading
import traceback

import select
import time

from _socket import socket, SOCK_DGRAM, SOL_SOCKET, SO_REUSEADDR, SO_BROADCAST

from listener import ReadBootProtocolPacket
from server_conf import DHCPServerConfiguration, get_host_ip_addresses
from server_helpers import DelayWorker, Transaction
from utils import HostDatabase, Host, CASEINSENSITIVE, GREATER, sorted_hosts, AuthDatabase


class DHCPServer(object):

    def __init__(self):
        self.ips = None

        self.configuration = DHCPServerConfiguration()

        configuration = DHCPServerConfiguration()
        configuration.router = configuration.captive_gateway
        configuration.ip_address_lease_time = configuration.login_wait_time
        self.pre_auth_configuration = configuration

        configuration = DHCPServerConfiguration()
        configuration.router = configuration.internet_gateway
        configuration.ip_address_lease_time = configuration.login_refresh_time
        self.post_auth_configuration = configuration

        self.auth = AuthDatabase()
        self.delay_worker = DelayWorker()
        self.hosts = HostDatabase(self.configuration.host_file)

        self.socket = socket(type=SOCK_DGRAM)
        self.socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        self.socket.bind((self.configuration.bind_address, 67))

        self.closed = False
        self.transactions = collections.defaultdict(lambda: Transaction(self))  # id: transaction
        self.time_started = time.time()

    def close(self):
        self.socket.close()
        self.closed = True
        self.delay_worker.close()
        for transaction in list(self.transactions.values()):
            transaction.close()

    def update(self, timeout=0):
        try:
            reads = select.select([self.socket], [], [], timeout)[0]
        except ValueError:
            # ValueError: file descriptor cannot be a negative integer (-1)
            return
        for _socket in reads:
            try:
                packet = ReadBootProtocolPacket(*_socket.recvfrom(4096))
            except OSError:
                # OSError: [WinError 10038] An operation was attempted on something that is not a socket
                pass
            else:
                self.received(packet)
        for transaction_id, transaction in list(self.transactions.items()):
            if transaction.is_done():
                transaction.close()
                self.transactions.pop(transaction_id)

    def received(self, packet):
        if not self.transactions[packet.transaction_id].receive(packet):
            self.configuration.debug('received:\n {}'.format(str(packet).replace('\n', '\n\t')))

    def client_has_chosen(self, packet):
        self.configuration.debug('client_has_chosen:\n {}'.format(str(packet).replace('\n', '\n\t')))
        host = Host.from_packet(packet)
        if not host.has_valid_ip():
            return
        self.hosts.replace(host)

    def is_valid_client_address(self, address):
        if address is None:
            return False
        a = address.split('.')
        s = self.configuration.subnet_mask.split('.')
        n = self.configuration.network.split('.')
        return all(s[i] == '0' or a[i] == n[i] for i in range(4))

    def get_ip_address(self, packet):
        mac_address = packet.client_mac_address
        requested_ip_address = packet.requested_ip_address
        known_hosts = self.hosts.get(mac=CASEINSENSITIVE(mac_address))
        ip = None
        if known_hosts:
            # 1. choose known ip address
            for host in known_hosts:
                if self.is_valid_client_address(host.ip):
                    ip = host.ip
            print('known ip:', ip)
        if ip is None and self.is_valid_client_address(requested_ip_address):
            # 2. choose valid requested ip address
            ip = requested_ip_address
            print('valid ip:', ip)
        if ip is None:
            # 3. choose new, free ip address
            chosen = False
            network_hosts = self.hosts.get(ip=self.configuration.network_filter())
            for ip in self.configuration.all_ip_addresses():
                if not any(host.ip == ip for host in network_hosts):
                    chosen = True
                    break
            if not chosen:
                # 4. reuse old valid ip address
                network_hosts.sort(key=lambda host: host.last_used)
                ip = network_hosts[0].ip
                assert self.is_valid_client_address(ip)
            print('new ip:', ip)
        if not any([host.ip == ip for host in known_hosts]):
            print('add', mac_address, ip, packet.host_name)
            self.hosts.replace(Host(mac_address, ip, packet.host_name or '', time.time()))
        return ip

    @property
    def server_identifiers(self):
        return get_host_ip_addresses()

    def broadcast(self, packet):
        self.configuration.debug('broadcasting:\n {}'.format(str(packet).replace('\n', '\n\t')))
        for addr in self.server_identifiers:
            broadcast_socket = socket(type=SOCK_DGRAM)
            broadcast_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
            broadcast_socket.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
            packet.server_identifier = addr
            broadcast_socket.bind((addr, 67))
            try:
                data = packet.to_bytes()
                broadcast_socket.sendto(data, ('255.255.255.255', 68))
                broadcast_socket.sendto(data, (addr, 68))
            finally:
                broadcast_socket.close()

    def run(self):
        while not self.closed:
            try:
                self.update(1)
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(e)
                traceback.print_exc()

    def run_in_thread(self):
        thread = threading.Thread(target=self.run)
        thread.start()
        return thread

    def debug_clients(self):
        for line in self.ips.all():
            line = '\t'.join(line)
            if line:
                self.configuration.debug(line)

    def get_all_hosts(self):
        return sorted_hosts(self.hosts.get())

    def get_current_hosts(self):
        return sorted_hosts(self.hosts.get(last_used=GREATER(self.time_started)))
