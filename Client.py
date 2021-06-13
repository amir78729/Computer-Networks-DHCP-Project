import socket, sys
from logging_functions import *

MAX_BYTES = 1024

SERVER_PORT = 67
CLIENT_PORT = 68



class DHCP_client(object):
    def client(self):
        print("DHCP client is starting...\n")
        dest = ('255.255.255.255', SERVER_PORT)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        src = ('0.0.0.0', CLIENT_PORT)
        s.bind(src)

        data = self.discover_get()
        s.sendto(data, dest)
        log_message(MessageType.DHCPDISCOVER, src=src, dst=dest)

        data, address = s.recvfrom(MAX_BYTES)
        # print(data)
        log_message(MessageType.DHCPOFFER, src=address, dst=src)

        data = self.request_get()
        s.sendto(data, dest)
        log_message(MessageType.DHCPREQUEST, src=src, dst=dest)

        data, address = s.recvfrom(MAX_BYTES)
        # print(data)
        log_message(MessageType.DHCPACK, src=address, dst=src)

    def discover_get(self):
        OP = bytes([0x01])
        HTYPE = bytes([0x01])
        HLEN = bytes([0x06])
        HOPS = bytes([0x00])
        XID = bytes([0x39, 0x03, 0xF3, 0x26])
        SECS = bytes([0x00, 0x00])
        FLAGS = bytes([0x00, 0x00])
        CIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        YIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        SIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        GIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        CHADDR1 = bytes([0x00, 0x05, 0x3C, 0x04])
        CHADDR2 = bytes([0x8D, 0x59, 0x00, 0x00])
        CHADDR3 = bytes([0x00, 0x00, 0x00, 0x00])
        CHADDR4 = bytes([0x00, 0x00, 0x00, 0x00])
        CHADDR5 = bytes(192)
        Magiccookie = bytes([0x63, 0x82, 0x53, 0x63])
        DHCPOptions1 = bytes([53, 1, 1])
        DHCPOptions2 = bytes([50, 4, 0xC0, 0xA8, 0x01, 0x64])

        package = OP + HTYPE + HLEN + HOPS + XID + SECS + FLAGS + CIADDR + YIADDR + SIADDR + GIADDR + CHADDR1 + CHADDR2 + CHADDR3 + CHADDR4 + CHADDR5 + Magiccookie + DHCPOptions1 + DHCPOptions2

        return package

    def request_get(self):
        OP = bytes([0x01])
        HTYPE = bytes([0x01])
        HLEN = bytes([0x06])
        HOPS = bytes([0x00])
        XID = bytes([0x39, 0x03, 0xF3, 0x26])
        SECS = bytes([0x00, 0x00])
        FLAGS = bytes([0x00, 0x00])
        CIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        YIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        SIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        GIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        CHADDR1 = bytes([0x00, 0x0C, 0x29, 0xDD])
        CHADDR2 = bytes([0x5C, 0xA7, 0x00, 0x00])
        CHADDR3 = bytes([0x00, 0x00, 0x00, 0x00])
        CHADDR4 = bytes([0x00, 0x00, 0x00, 0x00])
        CHADDR5 = bytes(192)
        Magiccookie = bytes([0x63, 0x82, 0x53, 0x63])
        DHCPOptions1 = bytes([53, 1, 3])
        DHCPOptions2 = bytes([50, 4, 0xC0, 0xA8, 0x01, 0x64])
        DHCPOptions3 = bytes([54, 4, 0xC0, 0xA8, 0x01, 0x01])

        package = OP + HTYPE + HLEN + HOPS + XID + SECS + FLAGS + CIADDR + YIADDR + SIADDR + GIADDR + CHADDR1 + CHADDR2 + CHADDR3 + CHADDR4 + CHADDR5 + Magiccookie + DHCPOptions1 + DHCPOptions2 + DHCPOptions3

        return package


if __name__ == '__main__':
    dhcp_client = DHCP_client()
    dhcp_client.client()