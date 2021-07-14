import socket
import time
import threading
import multiprocessing
import struct
from logging_functions import *
from random import randint
from uuid import getnode as get_mac
import uuid






def parse_dhcp(p):
    info = {
        'xid': p[4:8],
        'secs': p[8:10],
        'diaddr': p[12:16],
        'yiaddr': p[16:20],
        'siaddr': p[20:24],
        'giaddr': p[24:28],
        'chaddr': p[28:44]
    }
    return info


class DHCP_client(object):

    def __init__(self):
        self.MAX_BYTES = 1024
        self.SERVER_PORT = 67
        self.CLIENT_PORT = 68
        self.has_ip = False
        self.BACKOFF_CUTOFF = 120
        self.INITIAL_INTERVAL = 10

        self.dhcp_thread = None
        self.time_thread = None

    # def timer(self, t):
    #     while t:
    #         if self.has_ip:
    #             print('ip found. deactivation of timer')
    #             break
    #         time.sleep(1)
    #         print(t)
    #         t -= 1
    #     print('time is up')
    #     # self.dhcp_thread.s()

    def dhcp_client_thread_function(self):
        # self.time_thread = threading.Thread(target=self.timer, args=(3,))
        # self.time_thread.start()
        # self.time_thread.join(3)
        print("DHCP client is starting...\n")
        dest = ('255.255.255.255', self.SERVER_PORT)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        src = ('0.0.0.0', self.CLIENT_PORT)
        s.bind(src)
        ack = None

        mac = ':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff) for ele in range(0, 8 * 6, 8)][::-1])
        print(mac)

        discover = self.discover_get(mac)
        s.sendto(discover, dest)
        log_message(MessageType.DHCPDISCOVER, src=get_ip_from_bytes(parse_dhcp(discover)['yiaddr']), dst=dest[0])

        offer, address = s.recvfrom(self.MAX_BYTES)
        offer_info = parse_dhcp(offer)
        log_message(MessageType.DHCPOFFER, src=get_ip_from_bytes(offer_info['siaddr']), dst=src[0])
        print('OFFERED IP FROM {}: {}'.format(get_ip_from_bytes(offer_info['siaddr']),
                                              get_ip_from_bytes(offer_info['yiaddr'])))

        request = self.request_get(address[1], offer_info['yiaddr'])
        s.sendto(request, dest)
        log_message(MessageType.DHCPREQUEST, src=src[0], dst=dest[0])

        ack, address = s.recvfrom(self.MAX_BYTES)
        log_message(MessageType.DHCPACK, src=get_ip_from_bytes(offer_info['siaddr']),
                    dst=get_ip_from_bytes(offer_info['yiaddr']))
        print(ack)
        if ack:
            self.has_ip = True

    def client(self):

        print("DHCP client is starting...\n")
        dest = ('255.255.255.255', self.SERVER_PORT)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        src = ('0.0.0.0', self.CLIENT_PORT)
        s.bind(src)
        ack = None

        mac = ':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff) for ele in range(0,8*6,8)][::-1])
        print(mac)

        while True:
            # t = threading.Thread(target=self.timer, args=(2,))
            # t.start()

            discover = self.discover_get(mac)
            s.sendto(discover, dest)
            log_message(MessageType.DHCPDISCOVER, src=get_ip_from_bytes(parse_dhcp(discover)['yiaddr']), dst=dest[0])

            offer, address = s.recvfrom(MAX_BYTES)
            offer_info = parse_dhcp(offer)
            log_message(MessageType.DHCPOFFER, src=get_ip_from_bytes(offer_info['siaddr']), dst=src[0])
            print('OFFERED IP FROM {}: {}'.format(get_ip_from_bytes(offer_info['siaddr']), get_ip_from_bytes(offer_info['yiaddr'])))

            request = self.request_get(address[1], offer_info['yiaddr'])
            s.sendto(request, dest)
            log_message(MessageType.DHCPREQUEST, src=src[0], dst=dest[0])

            ack, address = s.recvfrom(MAX_BYTES)

            log_message(MessageType.DHCPACK, src=get_ip_from_bytes(offer_info['siaddr']), dst=get_ip_from_bytes(offer_info['yiaddr']))
            if ack:
                has_ip = True
                break

            t.join()
            if ack:
                print('DONE')
                break
            else:
                print('NO IP FOUND... TRYING AGAIN')

    def discover_get(self, mac):
        mac = str(mac).replace(":", "")
        mac = bytes.fromhex(mac)
        global Mac, XID
        # macb = getMacInBytes()
        Mac = mac
        transactionID = ''

        for i in range(4):
            t = randint(0, 255)
            t = str(hex(t//16)).replace('0x', '')+str(hex(t%16)).replace('0x', '')
            transactionID += t
        # print(transactionID)
        XID = bytearray.fromhex(transactionID)
        # print('xid',XID)

        packet = b''
        packet += b'\x01'  # Message type: Boot Request (1)
        packet += b'\x01'  # Hardware type: Ethernet
        packet += b'\x06'  # Hardware address length: 6
        packet += b'\x00'  # Hops: 0
        packet += XID  # Transaction ID
        packet += b'\x00\x00'  # Seconds elapsed: 0
        packet += b'\x80\x00'  # Bootp flags: 0x8000 (Broadcast) + reserved flags
        packet += b'\x00\x00\x00\x00'  # Client IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'  # Your (client) IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'  # Next server IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'  # Relay agent IP address: 0.0.0.0
        packet += mac  # Client MAC address:  "FF:C1:9A:D6:3E:00
        # packet += macb
        packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'  # Client hardware address padding: 00000000000000000000
        packet += b'\x00' * 67  # Server host name not given
        packet += b'\x00' * 125  # Boot file name not given
        packet += b'\x63\x82\x53\x63'  # Magic cookie: DHCP
        # DHCP IP Address
        packet += b'\x35\x01\x01'  # Option: (t=53,l=1) DHCP Message Type = DHCP Discover

        return packet

    def request_get(self, serverip, offerip):
        # offerip = bytes(map(int, str(offerip).split('.')))
        serverip = bytes(map(int, str(serverip).split('.')))

        packet = b''
        packet += b'\x01'  # Message type: Boot Request (1)
        packet += b'\x01'  # Hardware type: Ethernet
        packet += b'\x06'  # Hardware address length: 6
        packet += b'\x00'  # Hops: 0

        # print(xid_hex)
        packet += XID  # Transaction ID
        packet += b'\x00\x00'  # Seconds elapsed: 0
        packet += b'\x80\x00'  # Bootp flags: 0x8000 (Broadcast) + reserved flags
        packet += b'\x00\x00\x00\x00'  # Client IP address: 0.0.0.0
        packet += offerip  # Your (client) IP address: 0.0.0.0
        packet += serverip  # Next server IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'  # Relay agent IP address: 0.0.0.0
        # packet += b'\x00\x26\x9e\x04\x1e\x9b'   #Client MAC address: 00:26:9e:04:1e:9b
        packet += b'\xEE\xC1\x9A\xD6\x3E\x00'
        packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'  # Client hardware address padding: 00000000000000000000
        packet += b'\x00' * 67  # Server host name not given
        packet += b'\x00' * 125  # Boot file name not given
        packet += b'\x63\x82\x53\x63'  # Magic cookie: DHCP
        # DHCP IP Address
        packet += b'\x35\x01\x03'  # Option: (t=53,l=1) DHCP Message Type = DHCP Discover

        return packet

    def main(self):
        while not self.has_ip:
            self.dhcp_thread = threading.Thread(target=self.dhcp_client_thread_function)
            self.dhcp_thread.start()
            # self.dhcp_thread.join(30)
            # self.time_thread.join()





if __name__ == '__main__':
    dhcp_client = DHCP_client()
    dhcp_client.main()