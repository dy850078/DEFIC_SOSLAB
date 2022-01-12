import socket
import struct
import src.settings as settings
from src.tcp import unpack_tcp_option


class Packet:
    def __init__(self, packet: bytes):
        self.packet = packet
        self.l3_type = ''
        self.l4_type = ''
        self.eth_header = b''
        self.ip_header = b''
        self.tcp_header = b''
        self.tcp_option = b''
        self.icmp_header = b''
        self.padding = b''
        self.eth_field = {}
        self.ip_field = {}
        self.tcp_field = {}
        self.unpack()

    def unpack(self) -> None:
        self.set_eth_header()
        if self.l3_type == 'ip':
            self.set_ip_header()
            if self.l4_type == 'tcp':
                self.set_tcp_header()

    def set_eth_header(self) -> None:
        self.eth_header = self.packet[: settings.ETH_HEADER_LEN]
        eth = struct.unpack('!6s6sH', self.eth_header)
        eth_dMAC = eth[0]
        eth_sMAC = eth[1]
        eth_protocol = socket.ntohs(eth[2])

        if eth_protocol == 8:
            self.l3_type = 'ip'
        elif eth_protocol == 1544:
            self.l3_type = 'arp'
        else:
            self.l3_type = 'others'

        self.eth_field = {
            'dMAC': eth_dMAC,
            'sMAC': eth_sMAC,
            'protocol': eth_protocol
        }

    def set_ip_header(self) -> None:
        self.ip_header = self.packet[settings.ETH_HEADER_LEN: settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN]
        IHL_VERSION, TYPE_OF_SERVICE, total_len, pktID, FRAGMENT_STATUS, TIME_TO_LIVE, PROTOCOL, check_sum_of_hdr, \
        src_IP, dest_IP = struct.unpack('!BBHHHBBH4s4s', self.ip_header)

        if PROTOCOL == 1:
            self.l4_type = 'icmp'
        elif PROTOCOL == 6:
            self.l4_type = 'tcp'
        elif PROTOCOL == 17:
            self.l4_type = 'udp'
        else:
            self.l4_type = 'others'

        self.ip_field = {
            'IHL_VERSION': IHL_VERSION,
            'TYPE_OF_SERVICE': TYPE_OF_SERVICE,
            'total_len': total_len,
            'pktID': pktID,
            'FRAGMENT_STATUS': FRAGMENT_STATUS,
            'TIME_TO_LIVE': TIME_TO_LIVE,
            'PROTOCOL': PROTOCOL,
            'check_sum_of_hdr': check_sum_of_hdr,
            'src_IP': src_IP,
            'dest_IP': dest_IP
        }

    def set_tcp_header(self) -> None:
        packet = self.packet
        self.tcp_header = packet[settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN: settings.ETH_HEADER_LEN +
                                 settings.IP_HEADER_LEN + settings.TCP_HEADER_LEN]
        self.tcp_option = packet[settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN + settings.TCP_HEADER_LEN:
                                 settings.ETH_HEADER_LEN + self.ip_field['total_len']]
        self.padding = packet[settings.ETH_HEADER_LEN + self.ip_field['total_len']:]
        src_port, dest_port, seq, ack_num, offset, flags, window, checksum, urgent_ptr = struct.unpack(
            '!HHLLBBHHH', self.tcp_header)

        self.tcp_field = {
            'src_port': src_port,
            'dest_port': dest_port,
            'seq': seq,
            'ack_num': ack_num,
            'offset': offset,
            'flags': flags,
            'window': window,
            'checksum': checksum,
            'urgent_ptr': urgent_ptr
        }

        if self.tcp_option != b'':
            option_field, _ = unpack_tcp_option(self.tcp_option)
            self.tcp_field.update(option_field)


def diff_tcp(pkt1, pkt2):
    diff = {}
    eth_field_1, eth_field_2 = pkt1.eth_field, pkt2.eth_field
    ip_field_1, ip_field_2 = pkt1.ip_field, pkt2.ip_field
    tcp_field_1, tcp_field_2 = pkt1.tcp_field, pkt2.tcp_field

    # compare eth_field
    for i in eth_field_1:
        if eth_field_1[i] != eth_field_2[i]:
            diff[i] = (eth_field_1[i], eth_field_2[i])

    # compare ip_field
    for i in ip_field_1:
        if ip_field_1[i] != ip_field_2[i]:
            diff[i] = (ip_field_1[i], ip_field_2[i])

    # compare tcp_field
    base = tcp_field_1 if ip_field_1['total_len'] >= ip_field_2['total_len'] else tcp_field_2
    for i in base:
        if tcp_field_1[i] != tcp_field_2[i]:
            diff[i] = (tcp_field_1[i], tcp_field_2[i])

    return diff

