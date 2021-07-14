import socket
import sys
import os
import time

from logging_functions import *
MAX_BYTES = 1024

serverPort = 67
clientPort = 68


class DHCP_server(object):
    def server(self):
        print("DHCP server is starting...\n")

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        src = (socket.gethostbyname(socket.gethostname()), serverPort)
        s.bind(src)
        dest = ('255.255.255.255', clientPort)

        while 1:
            try:
                # print("Wait DHCP discovery.")
                discover, address = s.recvfrom(MAX_BYTES)

                # print("Receive DHCP discovery.")
                # print(discover)
                discover_info = parse_dhcp(discover)
                log_message(MessageType.DHCPDISCOVER, src=get_ip_from_bytes(discover_info['yiaddr']), dst=src[0])
                print('MAC ADDRESS: {}'.format(get_mac_from_bytes(discover_info['mac'])))

                offer_ip = '1.2.3.4'

                # print("Send DHCP offer.")
                offer = self.offer_get(offer_ip, discover_info['xid'], discover_info['mac'])
                s.sendto(offer, dest)
                log_message(MessageType.DHCPOFFER, src=src[0], dst=dest[0])
                while 1:
                    try:
                        # print("Wait DHCP request.")
                        request, address = s.recvfrom(MAX_BYTES)
                        request_info = parse_dhcp(request)
                        # print("Receive DHCP request.")
                        # print(data)
                        log_message(MessageType.DHCPREQUEST, src=get_ip_from_bytes(request_info['yiaddr']), dst=src[0])

                        # print("Send DHCP pack.\n")
                        # time.sleep(5)

                        ack = self.pack_get(offer_ip, discover_info['xid'], discover_info['mac'])
                        s.sendto(ack, dest)
                        log_message(MessageType.DHCPACK, src=src[0], dst=offer_ip)
                        break
                    except Exception as e:
                        exc_type, exc_obj, exc_tb = sys.exc_info()
                        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                        print(exc_type, fname, exc_tb.tb_lineno)
                        print(e)

            except Exception as e:
                exc_type, exc_obj, exc_tb = sys.exc_info()
                fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                print(exc_type, fname, exc_tb.tb_lineno)
                print(e)

    def offer_get(self, offer_ip, xid, mac):
        try:
            ip_as_bytes = bytes(map(int, str(offer_ip).split('.')))
            print(ip_as_bytes)
            serverip = bytes(map(int, str("127.0.0.1").split('.')))

            packet = b''
            packet += b'\x02'   # op
            packet += b'\x01'   # Hardware type: Ethernet
            packet += b'\x06'   # Hardware address length: 6
            packet += b'\x00'   # Hops: 0
            # print("xidddd{}".format(xid))
            # xid_hex = hex(xid).split('x')[-1]
            # print(xid_hex)
            # packet += bytearray.fromhex(xid_hex)  # Transaction ID
            packet += xid
            # TODO HANDLE ID FOR EACH CLIENT
            packet += b'\x00\x00'  # Seconds elapsed: 0
            packet += b'\x00\x00'  # Bootp flags: 0x8000 (Broadcast) + reserved flags
            packet += b'\x00\x00\x00\x00'  # Client IP address: 0.0.0.0
            packet += ip_as_bytes  # Your (client) IP address: 0.0.0.0
            packet += serverip  # Next server IP address: 0.0.0.0
            packet += b'\x00\x00\x00\x00'  # Relay agent IP address: 0.0.0.0
            # packet += b'\x00\x26\x9e\x04\x1e\x9b'   #Client MAC address: 00:26:9e:04:1e:9b
            # mac = self.connected_clients_list[xid]
            # mac = str(mac).replace(':', '')
            # packet += bytearray.fromhex(mac)
            # print(mac)
            packet += mac
            packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'  # Client hardware address padding: 00000000000000000000
            packet += b'\x00' * 67  # Server host name not given
            packet += b'\x00' * 125  # Boot file name not given
            packet += b'\x63\x82\x53\x63'  # Magic cookie: DHCP
            # DHCP IP Address
            packet += b'\x35\x01\x02'  # Option: (t=53,l=1) DHCP Message Type = DHCP Discover

            return packet
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            print(exc_type, fname, exc_tb.tb_lineno)
            print(e)

    def pack_get(self, offer_ip, xid, mac):
        try:
            ip_as_bytes = convert_ip_to_hex(offer_ip)
            serverip = bytes(map(int, str("127.0.0.1").split('.')))

            packet = b''
            packet += b'\x02'
            packet += b'\x01'  # Hardware type: Ethernet
            packet += b'\x06'  # Hardware address length: 6
            packet += b'\x00'  # Hops: 0

            # xid_hex = hex(xid).split('x')[-1]
            # print(xid_hex)
            # packet += bytes.fromhex(xid_hex)  # Transaction ID

            packet += xid
            # TODO HANDLE ID FOR EACH CLIENT
            packet += b'\x00\x00'  # Seconds elapsed: 0
            packet += b'\x00\x00'  # Bootp flags: 0x8000 (Broadcast) + reserved flags
            packet += b'\x00\x00\x00\x00'  # Client IP address: 0.0.0.0
            packet += ip_as_bytes  # Your (client) IP address: 0.0.0.0
            packet += serverip  # Next server IP address: 0.0.0.0
            packet += b'\x00\x00\x00\x00'  # Relay agent IP address: 0.0.0.0
            # packet += b'\x00\x26\x9e\x04\x1e\x9b'   #Client MAC address: 00:26:9e:04:1e:9b
            # mac = self.connected_clients_list[xid]
            # mac = str(mac).replace(':', '')
            # packet += bytes.fromhex(mac)
            packet += mac
            packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'  # Client hardware address padding: 00000000000000000000
            packet += b'\x00' * 67  # Server host name not given
            packet += b'\x00' * 125  # Boot file name not given
            packet += b'\x63\x82\x53\x63'  # Magic cookie: DHCP
            # DHCP IP Address
            packet += b'\x35\x01\x05'  # Option: (t=53,l=1) DHCP Message Type = DHCP Discover

            return packet
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            print(exc_type, fname, exc_tb.tb_lineno)
            print(e)

if __name__ == '__main__':
    dhcp_server = DHCP_server()
    dhcp_server.server()