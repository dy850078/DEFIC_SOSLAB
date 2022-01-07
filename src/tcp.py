import socket
import binascii
import struct
import array
import time
import src.settings as settings


class TcpConnect:

    def __init__(self, host):
        self.dip = host

        with open(settings.NICAddr) as f:
            mac = f.readline()
            self.mac = binascii.unhexlify(str.encode(''.join((mac.split(':'))))[:-1])

        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        self.sock.bind((settings.NIC, 0))

    def build_tcp_header_from_reply(self, tcp_len, seq, ack_num, src_port, dest_port, src_IP, dest_IP, flags):
        offset = tcp_len << 4
        reply_tcp_header = struct.pack('!HHIIBBHHH', src_port, dest_port, seq, ack_num, offset, flags, 0, 0, 0)
        pseudo_hdr = struct.pack('!4s4sBBH', src_IP, dest_IP, 0, socket.IPPROTO_TCP, len(reply_tcp_header))
        checksum = getTCPChecksum(pseudo_hdr + reply_tcp_header)
        reply_tcp_header = reply_tcp_header[:16] + struct.pack('H', checksum) + reply_tcp_header[18:]

        return reply_tcp_header


def os_build_tcp_header_from_reply(tcp_len, seq, ack_num, src_port, dest_port, src_IP, dest_IP, flags, window,
                                   reply_tcp_option):
    offset = tcp_len << 4
    reply_tcp_header = struct.pack('!HHIIBBHHH', src_port, dest_port, seq, ack_num, offset, flags, window, 0, 0)
    reply_tcp_header_option = reply_tcp_header + reply_tcp_option
    pseudo_hdr = struct.pack('!4s4sBBH', src_IP, dest_IP, 0, socket.IPPROTO_TCP, len(reply_tcp_header_option))
    checksum = getTCPChecksum(pseudo_hdr + reply_tcp_header_option)
    reply_tcp_header_option = reply_tcp_header_option[:16] + struct.pack('H', checksum) + reply_tcp_header_option[18:]

    return reply_tcp_header_option


def getIPChecksum(data):
    packet_sum = 0
    for index in range(0, len(data), 2):
        word = (data[index] << 8) + (data[index + 1])
        packet_sum = packet_sum + word
    packet_sum = (packet_sum >> 16) + (packet_sum & 0xffff)
    packet_sum = ~packet_sum & 0xffff
    return packet_sum


def getTCPChecksum(packet):
    if len(packet) % 2 != 0:
        packet += b'\0'

    res = sum(array.array("H", packet))
    res = (res >> 16) + (res & 0xffff)
    res += res >> 16

    return (~res) & 0xffff


def unpack_tcp_option(tcp_option):
    start_ptr = 0
    kind_seq = []
    option_val = {
        'padding': [],
        'mss': None,
        'shift_count': None,
        'sack_permitted': None,
        'ts_val': None,
        'ts_echo_reply': None
    }

    while start_ptr < len(tcp_option):
        kind, = struct.unpack('!B', tcp_option[start_ptr:start_ptr + 1])
        start_ptr += 1

        if kind == 1:
            option_val['padding'] = True
            kind_seq.append(kind)

        elif kind == 2:
            length, = struct.unpack('!B', tcp_option[start_ptr:start_ptr + 1])
            start_ptr += 1
            option_val['mss'], = struct.unpack('!H', tcp_option[start_ptr:start_ptr + length - 2])
            start_ptr += length - 2
            kind_seq.append(kind)

        elif kind == 3:
            length, = struct.unpack('!B', tcp_option[start_ptr:start_ptr + 1])
            start_ptr += 1
            option_val['shift_count'], = struct.unpack('!B', tcp_option[start_ptr:start_ptr + length - 2])
            start_ptr += length - 2
            kind_seq.append(kind)

        elif kind == 4:
            length, = struct.unpack('!B', tcp_option[start_ptr:start_ptr + 1])
            option_val['sack_permitted'] = True
            start_ptr += length - 1
            kind_seq.append(kind)

        elif kind == 8:
            length, = struct.unpack('!B', tcp_option[start_ptr:start_ptr + 1])
            start_ptr += 1
            option_val['ts_val'], option_val['ts_echo_reply'] = struct.unpack('!LL', tcp_option[
                                                                                     start_ptr:start_ptr + length - 2])
            start_ptr += length - 2
            kind_seq.append(kind)

    return option_val, kind_seq


def pack_tcp_option(option_val, kind_seq):
    reply_tcp_option = b''

    for kind in kind_seq:
        if kind == 2:
            kind = struct.pack('!B', 2)
            length = struct.pack('!B', 4)
            mss = struct.pack('!H', option_val['mss'])
            reply_tcp_option = reply_tcp_option + kind + length + mss

        elif kind == 4:
            kind = struct.pack('!B', 4)
            length = struct.pack('!B', 2)
            reply_tcp_option = reply_tcp_option + kind + length

        elif kind == 8:
            kind = struct.pack('!B', 8)
            length = struct.pack('!B', 10)
            ts_val = int(time.time())
            ts = struct.pack('!LL', ts_val, option_val['ts_echo_reply'])
            reply_tcp_option = reply_tcp_option + kind + length + ts

        elif kind == 1:
            kind = struct.pack('!B', 1)
            reply_tcp_option += kind

        elif kind == 3:
            kind = struct.pack('!B', 3)
            length = struct.pack('!B', 3)
            shift_count = struct.pack('!B', option_val['shift_count'])
            reply_tcp_option = reply_tcp_option + kind + length + shift_count

    return reply_tcp_option


def byte2mac(mac_byte):
    mac_str = "%02x:%02x:%02x:%02x:%02x:%02x" % struct.unpack("BBBBBB", mac_byte)

    return mac_str


def byte2ip(ip_byte):
    ip_str = socket.inet_ntoa(ip_byte)

    return ip_str
