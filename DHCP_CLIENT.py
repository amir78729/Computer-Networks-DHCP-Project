import ipaddress
import socket
import random
import socket
import struct
import plistlib
import sys 
from uuid import getnode as get_mac
import uuid
from random import randint
from time import *
import threading
from logging_functions import *
import math

# from goto import with_goto

# import dhcppython

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('0.0.0.0', 67))
Mac = ""
XID = ""
TIMEOUT = 10
BACKOFF_CUTOFF = 120
INITIAL_INTERVAL = 10
dis_time = 10

serverPort = 67
clientPort = 68


def buildPacket_discovery(mac):
    print('BUILDING DISCOVER PACKET...', end='')
    try:
        mac = str(mac).replace(":", "")
        mac = bytes.fromhex(mac)
    except ValueError:
        print(mac)
    global Mac, XID
    # print(mac)
    # macb = getMacInBytes()
    Mac = mac
    # print(Mac)
    transactionID = b''

    for i in range(4):
        t = randint(0, 255)
        transactionID += struct.pack('!B', t)
    XID = transactionID
    # print(XID)

    packet = b''
    packet += b'\x01'  # Message type: Boot Request (1)
    packet += b'\x01'  # Hardware type: Ethernet
    packet += b'\x06'  # Hardware address length: 6
    packet += b'\x00'  # Hops: 0
    packet += transactionID  # Transaction ID
    packet += b'\x00\x00'  # Seconds elapsed: 0
    packet += b'\x80\x00'  # Bootp flags:
    packet += b'\x00\x00\x00\x00'  # Client IP address: 0.0.0.0
    packet += b'\x00\x00\x00\x00'  # Your (client) IP address: 0.0.0.0
    packet += b'\x00\x00\x00\x00'  # Next server IP address: 0.0.0.0
    packet += b'\x00\x00\x00\x00'  # Relay agent IP address: 0.0.0.0
    packet += mac  # Client MAC address:  "FF:C1:9A:D6:3E:00

    packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    packet += b'\x00' * 67  # Server host name
    packet += b'\x00' * 125  # Boot file nam
    packet += b'\x63\x82\x53\x63'  # Magic cookie: DHCP
    # DHCP IP Address
    packet += b'\x35\x01\x01'
    print('DONE')
    return packet


def buildPacket_request(serverip, offerip):
    print('BUILDING REQUEST PACKET...', end='')
    # serverip = bytes(map(int, str(serverip).split('.')))

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
    print('DONE')
    return packet


def pkt_type(packet):
    if packet[len(packet) - 1] == 2:
        return "DHCPOFFER"
    if packet[len(packet) - 1] == 5:
        return "DHCPACK"


def parse_packet_client(pkt):
    yiaddr_bytes = pkt[16:20]
    yiaddr_original = ipaddress.IPv4Address(yiaddr_bytes)
    siaddr_bytes = pkt[20:24]
    siaddr_original = ipaddress.IPv4Address(siaddr_bytes)
    mac_byte = pkt[28:34]
    mac_original = mac_byte.hex(":")

    return yiaddr_original, siaddr_original, mac_original


def start_process(mac):
    global dis_time
    while True:
        sock.settimeout(2)
        discover = buildPacket_discovery(mac)
        sock.sendto(discover, ('<broadcast>', 68))
        log_message(MessageType.DHCPDISCOVER, src=get_ip_from_bytes(parse_dhcp(discover)['yiaddr']), dst='255.255.255.255')
        print('WAITING FOR THE DHCP SERVER...')
        get_ip = False
        getAck = False
        finish = False

        # offer
        try:
            msg, server_address = sock.recvfrom(4096)

            offer_info = parse_dhcp(msg)
            log_message(MessageType.DHCPOFFER, src=server_address[0], dst='255.255.255.255')
        except socket.timeout:
            print('NO OFFER RECEIVED!'
                  'SENDING DISCOVERY MESSAGE AGAIN...')
            # continue
            break

        try:
            data = msg.decode('utf-8')
            print('[SERVER] ' + data.upper())
            if "renew" in data:
                getAck = True
                get_ip = True
            if "blocked" or "reserved" in data:
                print('-'*70)
                finish = True
                quit()
        except (UnicodeDecodeError, AttributeError):
            parse_info = parse_dhcp(msg)
            offerip, serverip, mac = parse_info['yiaddr'], parse_info['siaddr'], parse_info['mac']
            print("[SERVER] offer ip \"{}\" for \"{}\"".format(get_ip_from_bytes(offerip), get_mac_from_bytes(mac)).upper())
            request = buildPacket_request(serverip, offerip)
            sock.sendto(request, server_address)
            log_message(MessageType.DHCPREQUEST, src='0.0.0.0', dst=server_address[0])
            print('waiting for ack'.upper())
            getAck = False
            sock.settimeout(2)
            try:
                msg, b = sock.recvfrom(4096)
                if msg:
                    print('ACK RECEIVED!')
                    log_message(MessageType.DHCPACK, src=server_address[0],
                                dst=get_ip_from_bytes(offer_info['yiaddr']))
                    getAck = True
            except socket.timeout:
                print("Time out ...".upper())

            if getAck == False:
                print("NO ACK FOUNDED")
                # continue
            else:
                print("ACK RECEIVED:)")
                get_ip = True
                # sys.exit()

                timer_thread = threading.Thread(target=lease_expire())
                timer_thread.start()
                break

    return getAck, get_ip, finish




def discovery_timer(initial_interval):
    global dis_time
    dis_time = initial_interval

    while dis_time:
        mins, secs = divmod(dis_time, 60)
        timer = '{:02d}:{:02d}'.format(mins, secs)
        # print(timer)
        sleep(1)
        dis_time -= 1


def lease_expire():
    print("expire timer begin")
    global expire
    lease = 12
    mins_total, secs_total = divmod(lease, 60)
    l = 0
    while lease >= l:
        mins, secs = divmod(l, 60)
        timer = '\r{:02d}:{:02d} / {:02d}:{:02d}'.format(mins, secs, mins_total, secs_total)
        print(timer, end='')
        sleep(1)
        l += 1
    expire=True
    print('\n' + 70*'-')


if __name__ == '__main__':

    mac = ':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff) for ele in range(0, 8 * 6, 8)][::-1]).upper()
    print(mac.replace(":", ""))
    print('484F6A1E593D   (reserved)')
    print('FFC19AD64D00   (blocked)')
    mac = input("Enter your mac address")

    getAck, getIp, finish = start_process(mac)

    offer_ip = ""
    flag = True
    getAck = False
    getIp = False

    prv_dis = INITIAL_INTERVAL
    while True:
        timer_thread = threading.Thread(target=discovery_timer, args=(dis_time,))
        timer_thread.start()

        while dis_time > 0:
            while not getAck:
                getAck, getIp, finish = start_process(mac)
                if finish:
                    sys.exit()

        if dis_time <= 0:
            print("Discovery time is up!\nupdating timer...".upper())
            print(' ?????? generating a random number for updating timer...'.upper(), end='')
            rand = random.uniform(0, 1)
            print(rand)

            if getAck is False:
                print(" ?????? Trying again for getting ip address".upper())
                if prv_dis >= BACKOFF_CUTOFF:
                    dis_time = BACKOFF_CUTOFF
                    print(" ?????? new discovery timer value: {}".format(dis_time))
                    print("     ?????? BACKOFF_CUTOFF = {}".format(dis_time))
                else:
                    generate = prv_dis * 2 * rand
                    dis_time = math.floor(generate)
                    print(" ?????? new discovery timer value: {}".format(dis_time))
                    print("     ?????? ??? prv_dis ?? 2 ?? random ??? = ??? {} ?? 2 ?? {} ??? = ???{}???".format(prv_dis, rand, generate))
                    prv_dis = dis_time

            elif getIp is True:
                if expire is True:
                    print(" ?????? IP expired")
                    expire = False
                    if prv_dis >= BACKOFF_CUTOFF:
                        dis_time = BACKOFF_CUTOFF
                        print(" ?????? new discovery timer value: {}".format(dis_time))
                        print("     ?????? BACKOFF_CUTOFF = {}".format(dis_time))
                    else:
                        generate = prv_dis * 2 * rand
                        dis_time = math.floor(generate)
                        print(" ?????? new discovery timer value: {}".format(dis_time))
                        print("     ?????? ??? prv_dis ?? 2 ?? random ??? = ??? {} ?? 2 ?? {} ??? = ???{}???".format(prv_dis, rand, generate))
                        prv_dis = dis_time
                else:
                    while expire is False:
                        pass
                    expire = False
                    if prv_dis >= BACKOFF_CUTOFF:
                        dis_time = BACKOFF_CUTOFF
                        print(" ?????? new discovery timer value: {}".format(dis_time))
                        print("     ?????? BACKOFF_CUTOFF = {}".format(dis_time))
                    else:
                        generate = prv_dis * 2 * rand
                        dis_time = math.floor(generate)
                        print(" ?????? new discovery timer value: {}".format(dis_time))
                        print("     ?????? ??? prv_dis ?? 2 ?? random ??? = ??? {} ?? 2 ?? {} ??? = ???{}???".format(prv_dis, rand, generate))
                        prv_dis = dis_time

        getIp = False
        getAck = False
