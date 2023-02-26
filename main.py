from server import DHCPServer
from server_conf import DHCPServerConfiguration


def main():
    configuration = DHCPServerConfiguration()
    server = DHCPServer(configuration)

    for ip in server.configuration.all_ip_addresses():
        assert ip == server.configuration.network_filter()

    server.run()


if __name__ == '__main__':
    main()
