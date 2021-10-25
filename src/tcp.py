import socket
import binascii
import struct
import array
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
