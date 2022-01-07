import socket
import struct
import src.settings as settings


class Packet:
    def __init__(self, packet: bytes):
        self.packet = packet
        self.l3_type = None
        self.l4_type = None
        self.eth_header = None
        self.ip_header = None
        self.tcp_header = None
        self.tcp_option = None
        self.icmp_header = None
        self.eth_field = {}
        self.ip_field = {}
        self.tcp_field = {}
        self.icmp_field = {}

    def set_eth_header(self) -> None:
        self.eth_header = self.packet[: settings.ETH_HEADER_LEN]
        eth = struct.unpack('!6s6sH', self.eth_header)
        eth_protocol = socket.ntohs(eth[2])
        self.eth_field = {
            'protocol': eth_protocol
        }

    def set_ip_header(self) -> None:
        self.ip_header = self.packet[settings.ETH_HEADER_LEN: settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN]
        IHL_VERSION, TYPE_OF_SERVICE, total_len, pktID, FRAGMENT_STATUS, TIME_TO_LIVE, PROTOCOL, check_sum_of_hdr, \
        src_IP, dest_IP = struct.unpack('!BBHHHBBH4s4s', self.ip_header)
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
        self.tcp_option = packet[settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN + settings.TCP_HEADER_LEN:]
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






