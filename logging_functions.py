import datetime
import enum


class MessageType(enum.Enum):
    DHCPDISCOVER = 'DHCPDISCOVER'
    DHCPREQUEST = 'DHCPREQUEST'
    DHCPOFFER = 'DHCPOFFER'
    DHCPACK = 'DHCPACK'


def log_message(typ, src, dst):
    if typ.value in ['DHCPDISCOVER', 'DHCPREQUEST']:
        print("[CLIENT → SERVER]({})".format(datetime.datetime.now()))
        print(' ├─ SRC.: {}:{}'.format(src[0], src[1]))
        print(' ├─ DST.: {}:{}'.format(dst[0], dst[1]))
        print(' └─ TYPE: {}'.format(typ.value))
    elif typ.value in ['DHCPOFFER', 'DHCPACK']:
        print("[SERVER → CLIENT]({})".format(datetime.datetime.now()))
        print(' ├─ SRC.: {}:{}'.format(src[0], src[1]))
        print(' ├─ DST.: {}:{}'.format(dst[0], dst[1]))
        print(' └─ TYP.: {}'.format(typ.value))
    else:
        print('UNKNOWN MESSAGE')
    print()