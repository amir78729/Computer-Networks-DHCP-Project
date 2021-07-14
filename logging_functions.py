import datetime
import enum


class MessageType(enum.Enum):
    DHCPDISCOVER = 'DHCPDISCOVER'
    DHCPREQUEST = 'DHCPREQUEST'
    DHCPOFFER = 'DHCPOFFER'
    DHCPACK = 'DHCPACK'


def log_message(typ, src, dst):
    print('-'*50)
    if typ.value in ['DHCPDISCOVER', 'DHCPREQUEST']:
        print("[CLIENT → SERVER]({})".format(datetime.datetime.now()))
        print(' ├─ SRC.: {}:68'.format(src))
        print(' ├─ DST.: {}:67'.format(dst))
        print(' └─ TYPE: {}'.format(typ.value))
    elif typ.value in ['DHCPOFFER', 'DHCPACK']:
        print("[SERVER → CLIENT]({})".format(datetime.datetime.now()))
        print(' ├─ SRC.: {}:67'.format(src))
        print(' ├─ DST.: {}:68'.format(dst))
        print(' └─ TYP.: {}'.format(typ.value))
    else:
        print('UNKNOWN MESSAGE')
    print('-' * 50)


def parse_dhcp(p):
    info = {
        'xid': p[4:8],
        'secs': p[8:10],
        'diaddr': p[12:16],
        'yiaddr': p[16:20],
        'siaddr': p[20:24],
        'giaddr': p[24:28],
        'chaddr': p[28:44],
        'mac': p[28:34],
    }
    return info

def get_ip_from_bytes(bytes_ip):
    return '{}.{}.{}.{}'.format(bytes_ip[0], bytes_ip[1], bytes_ip[2], bytes_ip[3])


def convert_ip_to_hex(ip):
    return bytes(map(int, str(ip).split('.')))

def get_mac_from_bytes(mac_byte):
    mac = []
    for m in range(len(mac_byte)):
        t = mac_byte[m]
        t = str(hex(t // 16)).replace('0x', '') + str(hex(t % 16)).replace('0x', '')
        mac.append(t)
    return '{}:{}:{}:{}:{}:{}'.format(mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
