import ipaddress
import json
import os
import struct
import sys
import threading
import socket
import logging
import time
import random
from OuiLookup import OuiLookup
from logging_functions import *
from concurrent.futures import ThreadPoolExecutor  # Python 3.2


class Server:

    def __init__(self):
        self.serverIP = socket.gethostbyname(socket.gethostname())
        # self.serverIP = '127.0.0.1'

        print('Initializing DHCP Server. ({})'.format(self.serverIP))
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.bind((self.serverIP, 68))
        self.connected_clients_list = dict()
        self.OccupyIP = []
        self.waitIP=[]
        self.Serviced_ClientsInfo_print = []
        self.client_ips = dict()
        self.reserved = dict()
        self.leaseThreads = dict()

        self.startInterval = 0
        self.stopInterval = 0

        f = open("configs.json")
        self.data = json.load(f)
        f.close()
        self.pool_mode = self.data["pool_mode"]
        self.range_from = self.data["range"]["from"]
        self.range_to = self.data["range"]["to"]
        self.subnet_block = self.data["subnet"]["ip_block"]
        self.subnet_mask = self.data["subnet"]["subnet_mask"]
        self.lease_time = self.data["lease_time"]
        if self.pool_mode == "range":
            self.startInterval = self.ip2long(self.range_from)
            self.stopInterval = self.ip2long(self.range_to)
        elif self.pool_mode == "subnet":
            self.startInterval = self.ip2long(self.subnet_block)
            self.stopInterval = self.ip2long(self.subnet_mask)
        if len(self.data["reservation_list"]) != 0:
            for key in self.data["reservation_list"]:
                self.reserved[key] = self.data["reservation_list"][key]
                self.OccupyIP.append(self.data["reservation_list"][key])

    def start(self):
        pass

    def handle_client(self, xid, mac, addrss,server):
        pass

    def get_discovery(self):
        workers = 5
        items = 15
        executor = ThreadPoolExecutor(max_workers=workers)

        while True:
            try:
                print('waiting for a client...'.upper())
                msg, client = self.sock.recvfrom(4096)
                msg_type = self.packet_type(msg)
                if "DHCPDISCOVER" in msg_type:
                    log_message(MessageType.DHCPDISCOVER, src='0.0.0.0', dst='255.255.255.255')

                    parse_info = parse_dhcp(msg)
                    xid, mac = parse_info['xid'], parse_info['mac']
                    mac_string = get_mac_from_bytes(mac)
                    print('CLIENT MAC ADDRESS: ' + mac_string)
                    print('checking mac address'.upper())
                    if mac not in self.client_ips:
                        macUpper = str(mac_string).upper()
                        block = self.block_or_not(macUpper)
                        reserve = self.reserved_or_not(macUpper)
                        print()
                        if block:
                            print("This client is blocked".upper())
                            string = "You are blocked! "
                            self.sock.sendto(string.encode(), ('255.255.255.255', 67))

                        elif reserve:
                            reserved_ip = self.reserved[macUpper]
                            print("This client is reserved with ip {}".format(reserved_ip).upper())
                            string = "You are reserved with ip {}!".format(reserved_ip)
                            self.sock.sendto(string.encode(), ('255.255.255.255', 67))

                        else:
                            if mac not in self.connected_clients_list:
                                self.connected_clients_list[mac] = xid
                            occupy_ip_len = len(self.OccupyIP)
                            all_ip_number = self.stopInterval - self.startInterval + 1
                            if occupy_ip_len == all_ip_number:
                                string = "sorry all ips are occupied"
                                self.sock.sendto(string.encode(), ('255.255.255.255', 67))
                            else:
                                flag = True
                                offer = 0
                                offer_ip = ""
                                while flag:

                                    offer = random.randint(self.startInterval, self.stopInterval)
                                    offer_ip = self.long2ip(offer)

                                    if offer_ip in self.OccupyIP and offer_ip in self.waitIP:
                                        continue
                                    else:
                                        print("CANDIDATE IP FOR OFFER: {}".format(offer_ip))
                                        self.waitIP.append(offer_ip)
                                        flag = False

                                pkt = self.buildPacket_offer(offer_ip, xid, mac)

                                self.sock.sendto(pkt, ('255.255.255.255', 67))

                                log_message(MessageType.DHCPOFFER, src='127.0.0.1',
                                            dst='255.255.255.255')
                                msg, client_address = self.sock.recvfrom(4096)
                                print('Waiting for request...'.upper())
                                request_info = parse_dhcp(msg)
                                xid, chaddrss = request_info['xid'], request_info['chaddr']
                                log_message(MessageType.DHCPREQUEST, src=get_ip_from_bytes(request_info['yiaddr']),
                                            dst='255.255.255.255')
                                print('CLIENT REQUESTED FOR \"{}\"'.format(offer_ip))
                                pkt = self.buildPacket_Ack(offer_ip, xid, mac)
                                self.sock.sendto(pkt, ('255.255.255.255', 67))

                                log_message(MessageType.DHCPACK, src='127.0.0.1',
                                            dst=offer_ip)

                                lease_time = self.lease_time


                else:
                    print('mac in self.client_ips')
                    prev_ip = self.client_ips[mac]
                    prev_thread = self.leaseThreads[mac]
                    print("You are in list yet with {} ,lease time renew".format(prev_ip))
                    string = "You are in list yet with {} ,lease time renew".format(prev_ip)
                    self.sock.sendto(string.encode(), ('255.255.255.255', 67))
                    index = -1
                    prev_thread.join()
                    self.leaseThreads.pop(mac)
                    lease_thread = threading.Thread(target=self.lease, args=(mac, prev_ip, xid, index))
                    self.leaseThreads[mac] = lease_thread
                    lease_thread.start()

            except Exception as e:
                print(e)


    def packet_type(self, packet):
        if packet[len(packet) - 1] == 1:
            return "DHCPDISCOVER"
        if packet[len(packet) - 1] == 3:
            return "DHCPREQUEST"


    def ip2long(self, ip):
        packedIP = socket.inet_aton(ip)
        return struct.unpack("!L", packedIP)[0]


    def long2ip(self, data):
        return socket.inet_ntoa(struct.pack('!L', data))


    def isReserved(self, ip):
        Reserved = False
        split = str(ip).split(".")
        if split[len(split) - 1] == "0" or split[len(split) - 1] == "1":
            Reserved = True
        return Reserved


    def buildPacket_offer(self, offer_ip, xid, mac):
        print('building offer packet...'.upper(), end='')
        try:
            ip_as_bytes = bytes(map(int, str(offer_ip).split('.')))
            serverip = bytes(map(int, str("127.0.0.1").split('.')))
            packet = b''
            packet += b'\x02'  # op
            packet += b'\x01'  # Hardware type: Ethernet
            packet += b'\x06'  # Hardware address length: 6
            packet += b'\x00'  # Hops: 0
            packet += xid
            packet += b'\x00\x00'  # Seconds elapsed: 0
            packet += b'\x00\x00'  # Bootp flags: 0x8000 (Broadcast) + reserved flags
            packet += b'\x00\x00\x00\x00'  # Client IP address: 0.0.0.0
            packet += ip_as_bytes  # Your (client) IP address: 0.0.0.0
            packet += serverip  # Next server IP address: 0.0.0.0
            packet += b'\x00\x00\x00\x00'  # Relay agent IP address: 0.0.0.0
            packet += mac
            packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'  # Client hardware address padding: 00000000000000000000
            packet += b'\x00' * 67  # Server host name not given
            packet += b'\x00' * 125  # Boot file name not given
            packet += b'\x63\x82\x53\x63'  # Magic cookie: DHCP
            # DHCP IP Address
            packet += b'\x35\x01\x02'  # Option: (t=53,l=1) DHCP Message Type = DHCP Discover
            print('DONE')
            return packet
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            print(exc_type, fname, exc_tb.tb_lineno)
            print(e)


    def buildPacket_Ack(self, offer_ip, xid, mac):
        print('BUILDING ACK PACKET...', end='')
        ip_as_bytes = bytes(map(int, str(offer_ip).split('.')))
        serverip = bytes(map(int, str("127.0.0.1").split('.')))
        packet = b''
        packet += b'\x02'
        packet += b'\x01'  # Hardware type: Ethernet
        packet += b'\x06'  # Hardware address length: 6
        packet += b'\x00'  # Hops: 0
        packet += xid
        packet += b'\x00\x00'  # Seconds elapsed: 0
        packet += b'\x00\x00'  # Bootp flags
        packet += b'\x00\x00\x00\x00'  # Client IP address: 0.0.0.0
        packet += ip_as_bytes  # Your (client) IP address: 0.0.0.0
        packet += serverip  # Next server IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'  # Relay agent IP address: 0.0.0.0
        packet += mac
        packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        packet += b'\x00' * 67  # Server host name
        packet += b'\x00' * 125  # Boot file name
        packet += b'\x63\x82\x53\x63'  # Magic cookie: DHCP
        # DHCP IP Address
        packet += b'\x35\x01\x05'
        print("DONE")
        return packet


    def parse_packet_server(self, pkt):
        xid = int(pkt[4:8].hex(), 16)
        mac_byte = pkt[28:34]
        mac_original = mac_byte.hex(":")

        return xid, mac_original


    def block_or_not(self, mac):
        block = False
        print(' ├─ BLACK LIST')
        for i in self.data["black_list"]:
            if i == mac:
                print(' │     └─ {} (SHOULD BE BLOCKED!)'.format(i))
                block = True
            else:
                print(' │     └─ {}'.format(i))
        return block


    def reserved_or_not(self, mac):
        print(' │')
        print(' └─ RESERVED IP ADDRESSES')
        reserved = False
        for i in self.reserved.keys():
            if i == mac:
                print('       └─ {} HAS IP {}. (RESERVED!)'.format(i, self.reserved[i]))
                reserved = True
            else:
                print('       └─ {} HAS IP {}.'.format(i, self.reserved[i]))

        return reserved


    def lease(self, mac, ip, xid, index):
        timeOut = self.lease_time
        print("lease start for {}".format(mac))

        while timeOut:
            if mac not in self.client_ips:
                self.client_ips[mac] = ip
                self.OccupyIP.append(ip)
                self.connected_clients_list[mac] = xid
            mins, secs = divmod(timeOut, 60)
            timer = '{:02d}:{:02d}'.format(mins, secs)

            time.sleep(1)
            timeOut -= 1
            self.Serviced_ClientsInfo_print[index][3] = timeOut
        print("lease expire for {}".format(mac))
        self.OccupyIP.remove(ip)
        self.waitIP.remove(ip)
        self.connected_clients_list.pop(str(mac))
        self.client_ips.pop(str(mac))


if __name__ == '__main__':
    b = Server()
    b.get_discovery()
