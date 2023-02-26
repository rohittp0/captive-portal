from server import DHCPServer


def main():
    server = DHCPServer()

    for ip in server.configuration.all_ip_addresses():
        assert ip == server.configuration.network_filter()

    server.run()


if __name__ == '__main__':
    main()
