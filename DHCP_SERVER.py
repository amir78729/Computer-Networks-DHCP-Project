import ipaddress
import json
import struct
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
        print('Initializing DHCP Server')
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.bind(('', 68))
        self.connected_clients_list = dict()
        # self.clients = []
        self.OccupyIP = []
        self.waitIP=[]
        self.Serviced_ClientsInfo_print = []
        self.client_ips = dict()
        self.reserved = dict()
        self.leaseThreads = dict()

        self.startInterval = 0
        self.stopInterval = 0
        self.serverIP = socket.gethostbyname(socket.gethostname())
        f = open("configs.json")
        data = json.load(f)
        f.close()
        self.pool_mode = data["pool_mode"]
        self.range_from = data["range"]["from"]
        self.range_to = data["range"]["to"]
        self.subnet_block = data["subnet"]["ip_block"]
        self.subnet_mask = data["subnet"]["subnet_mask"]
        self.lease_time = data["lease_time"]
        if self.pool_mode == "range":
            self.startInterval = self.ip2long(self.range_from)
            self.stopInterval = self.ip2long(self.range_to)
        elif self.pool_mode == "subnet":
            self.startInterval = self.ip2long(self.subnet_block)
            self.stopInterval = self.ip2long(self.subnet_mask)
        if len(data["reservation_list"]) != 0:
            for key in data["reservation_list"]:
                self.reserved[key] = data["reservation_list"][key]
                self.OccupyIP.append(data["reservation_list"][key])

    def handle_client(self, xid, mac, addrss,server):

        if mac not in self.client_ips:
            macUpper = str(mac).upper()
            block = self.block_or_not(macUpper)
            reserve = self.reserved_or_not(macUpper)

            print(reserve)
            if block:
                print("This client is blocked")
                string = "You are blocked "
                self.sock.sendto(string.encode(), ('255.255.255.255', 67))
            if reserve:
                reserved_ip = self.reserved[macUpper]
                print("This client is reserved with ip {}".format(reserved_ip))
                string = "You are reserved with ip {}".format(reserved_ip)
                self.sock.sendto(string.encode(), ('255.255.255.255', 67))
                PCName = OuiLookup().query(mac)
                client_info = [PCName, mac, reserved_ip, "infinity"]
                self.Serviced_ClientsInfo_print.append(client_info)

            if not block and not reserve:
                if mac not in self.connected_clients_list:
                    self.connected_clients_list[mac] = xid
                # print(self.connected_clients_list)
                occupy_ip_len = len(self.OccupyIP)
                all_ip_number = self.stopInterval - self.startInterval + 1
                if occupy_ip_len == all_ip_number:
                    string = "sorry all ips are occupied"
                    self.sock.sendto(string.encode(), ('255.255.255.255', 67))
                else:
                    flag = True
                    offer = 0
                    offer_ip = ""
                    while (flag):

                        offer = random.randint(self.startInterval, self.stopInterval)
                        offer_ip = self.long2ip(offer)

                        if offer_ip in self.OccupyIP and offer_ip in self.waitIP :
                            continue
                        else:
                            print("Server want offer {}".format(offer_ip))
                            self.waitIP.append(offer_ip)

                            flag = False
                    print("lets offer to {}".format(mac))
                    pkt = self.buildPacket_offer(offer_ip, xid, mac)
                    self.sock.sendto(pkt, ('255.255.255.255', 67))
                    msg, client = server.recvfrom(1024)

                    print(self.packet_type(msg))
                    parse_info = parse_dhcp(msg)
                    id, chaddrss = parse_info['xid'], parse_info['chaddr']
                    # yiaddr_bytes = msg[16:20]
                    # yiaddr_original = ipaddress.IPv4Address(yiaddr_bytes)
                    # print("client want {}".format(yiaddr_original))

                    pkt = self.buildPacket_Ack(offer_ip, xid, mac)
                    # start lease time timer
                    time.sleep(5)
                    self.sock.sendto(pkt, ('255.255.255.255', 67))
                    lease_time = self.lease_time
                    PCName = OuiLookup().query(mac)
                    client_info = [PCName, mac, offer_ip, lease_time]
                    self.Serviced_ClientsInfo_print.append(client_info)
                    index = self.Serviced_ClientsInfo_print.index(client_info)
                    self.OccupyIP.append(offer_ip)
                    self.client_ips[mac] = offer_ip
                    lease_thread = threading.Thread(target=self.lease, args=(mac, offer_ip, xid, index))
                    self.leaseThreads[mac] = lease_thread
                    lease_thread.start()



        else:
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

    def get_discovery(self):
        workers = 5
        items = 15
        executor = ThreadPoolExecutor(max_workers=workers)
        executor.submit(self.show_clients())
        # show_client_thread = threading.Thread(target=self.show_clients())
        # show_client_thread.start()
        while True:
            msg, client = self.sock.recvfrom(1024)

            # print('Received data from client {} {}'.format(client, msg))
            log_message(MessageType.DHCPDISCOVER, src=get_ip_from_bytes(parse_dhcp(msg)['yiaddr']), dst=client[0])
            msg_type = self.packet_type(msg)
            print(msg_type)
            if "DHCPDISCOVER" in msg_type:
                parse_info = parse_dhcp(msg)
                client_xid, client_mac = parse_info['xid'], parse_info['mac']
                print("Client xid {}".format(client_xid))
                server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server.bind(("127.0.0.1", 68))


                executor.submit(self.handle_client,client_xid, client_mac, client,server)

            # t = threading.Thread(target=self.handle_client, args=(client_xid, client_mac, client,))
            # # self.connected_clients_list[client_xid]=client_mac
            # t.start()


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
        ip_as_bytes = bytes(map(int, str(offer_ip).split('.')))
        serverip = bytes(map(int, str("127.0.0.1").split('.')))

        packet = b''
        packet += b'\x02'  # opcode
        packet += b'\x01'  # Hardware type: Ethernet
        packet += b'\x06'  # Hardware address length: 6
        packet += b'\x00'  # Hops: 0
        # print("xidddd{}".format(xid))
        xid_hex = hex(xid).split('x')[-1]
        print(xid_hex)
        packet += bytearray.fromhex(xid_hex)  # Transaction ID

        packet += b'\x00\x00'  # Seconds elapsed: 0
        packet += b'\x00\x00'  # Bootp flags
        packet += b'\x00\x00\x00\x00'  # Client IP address: 0.0.0.0
        packet += ip_as_bytes  # Your (client) IP address: 0.0.0.0
        packet += serverip  # Next server IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'  # Relay agent IP address: 0.0.0.0
        # packet += b'\x00\x26\x9e\x04\x1e\x9b'   #Client MAC address: 00:26:9e:04:1e:9b
        # mac = self.connected_clients_list[xid]
        mac = str(mac).replace(':', '')
        packet += bytearray.fromhex(mac)
        packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        packet += b'\x00' * 67  # Server host name
        packet += b'\x00' * 125  # Boot file name
        packet += b'\x63\x82\x53\x63'  # Magic cookie: DHCP
        # DHCP IP Address
        packet += b'\x35\x01\x02'

        return packet


    def buildPacket_Ack(self, offer_ip, xid, mac):
        ip_as_bytes = bytes(map(int, str(offer_ip).split('.')))
        serverip = bytes(map(int, str("127.0.0.1").split('.')))

        packet = b''
        packet += b'\x02'
        packet += b'\x01'  # Hardware type: Ethernet
        packet += b'\x06'  # Hardware address length: 6
        packet += b'\x00'  # Hops: 0

        xid_hex = hex(xid).split('x')[-1]
        print(xid_hex)
        packet += bytes.fromhex(xid_hex)  # Transaction ID

        packet += b'\x00\x00'  # Seconds elapsed: 0
        packet += b'\x00\x00'  # Bootp flags
        packet += b'\x00\x00\x00\x00'  # Client IP address: 0.0.0.0
        packet += ip_as_bytes  # Your (client) IP address: 0.0.0.0
        packet += serverip  # Next server IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'  # Relay agent IP address: 0.0.0.0
        # packet += b'\x00\x26\x9e\x04\x1e\x9b'   #Client MAC address: 00:26:9e:04:1e:9b
        # mac = self.connected_clients_list[xid]
        mac = str(mac).replace(':', '')
        packet += bytes.fromhex(mac)
        packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        packet += b'\x00' * 67  # Server host name
        packet += b'\x00' * 125  # Boot file name
        packet += b'\x63\x82\x53\x63'  # Magic cookie: DHCP
        # DHCP IP Address
        packet += b'\x35\x01\x05'

        return packet


    def parse_packet_server(self, pkt):
        xid = int(pkt[4:8].hex(), 16)
        # print(pkt[28:44])
        mac_byte = pkt[28:34]
        mac_original = mac_byte.hex(":")

        return xid, mac_original


    def block_or_not(self, mac):
        block = False
        f = open("C:\\Users\\Asus\\PycharmProjects\\CN_P3\\configs.json")
        data = json.load(f)
        f.close()
        if mac in data["black_list"]:
            block = True
        return block


    def reserved_or_not(self, mac):
        reserved = False
        print(self.reserved)
        print(mac)
        if str(mac) in self.reserved:
            reserved = True
        return reserved


    def show_clients(self):
        pass
        # while True:
        #         show=input()
        #         if show=="show_clients":
        #             print(self.Serviced_ClientsInfo_print)


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
            # print(self.Serviced_ClientsInfo_print)
        print("lease expire for {}".format(mac))
        self.OccupyIP.remove(ip)
        self.waitIP.remove(ip)
        self.connected_clients_list.pop(str(mac))
        self.client_ips.pop(str(mac))


def show(server):
    print("hii")
    while True:

        show=input()
        if show=="show_clients":
            print(Server(server).Serviced_ClientsInfo_print)


if __name__ == '__main__':
    # Make sure all log messages show up

    b = Server()


    # t = threading.Thread(target=b.get_discovery())
    #
    # t.start()
    b.get_discovery()

    # t2 = threading.Thread(target=show(b))
    #
    # t2.start()