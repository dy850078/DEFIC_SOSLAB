import logging
import socket
import struct
import src.settings as settings


class Packet:
    def __init__(self, packet=b'', proc=None, l2_field=None, l3_field=None, l4_field=None, data=''):
        self.packet = packet
        self.l3 = proc if proc in settings.L3_PROC else 'ip'
        self.l4 = proc if proc in settings.L4_PROC else ''
        self.l2_header = b''
        self.l3_header = b''
        self.l4_header = b''
        self.l2_field = l2_field
        self.l3_field = l3_field
        self.l4_field = l4_field
        self.data = data

    def unpack(self) -> None:
        self.unpack_l2_header()
        self.unpack_l3_header(self.l3)
        if self.l4 != '':
            self.unpack_l4_header(self.l4)

    def unpack_l2_header(self) -> None:
        self.l2_header = self.packet[: settings.ETH_HEADER_LEN]
        eth = struct.unpack('!6s6sH', self.l2_header)
        eth_dMAC = eth[0]
        eth_sMAC = eth[1]
        eth_protocol = eth[2]

        if eth_protocol == 2048:
            self.l3 = 'ip'
        elif eth_protocol == 2054:
            self.l3 = 'arp'
        else:
            self.l3 = 'others'

        self.l2_field = {
            'dMAC': eth_dMAC,
            'sMAC': eth_sMAC,
            'protocol': eth_protocol,
        }

    def unpack_l3_header(self, l3) -> None:
        if l3 == 'ip':
            self.unpack_ip_header()
        elif l3 == 'arp':
            self.unpack_arp_header()

    def unpack_l4_header(self, l4) -> None:
        if l4 == 'tcp':
            self.unpack_tcp_header()
        elif l4 == 'udp':
            self.unpack_udp_header()
        elif l4 == 'icmp':
            self.unpack_icmp_header()

    def unpack_arp_header(self) -> None:
        self.l3_header = self.packet[settings.ETH_HEADER_LEN: settings.ETH_HEADER_LEN + settings.ARP_HEADER_LEN]
        hw_type, proto_type, hw_size, proto_size, opcode, sender_mac, sender_ip, recv_mac, recv_ip = struct.unpack(
            '2s2s1s1s2s6s4s6s4s', self.l3_header)

        self.l3_field = {
            'hw_type': hw_type,
            'proto_type': proto_type,
            'hw_size': hw_size,
            'proto_size': proto_size,
            'opcode': opcode,
            'sender_mac': sender_mac,
            'sender_ip': sender_ip,
            'recv_mac': recv_mac,
            'recv_ip': recv_ip
        }

    def unpack_ip_header(self) -> None:
        self.l3_header = self.packet[settings.ETH_HEADER_LEN: settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN]
        IHL_VERSION, TYPE_OF_SERVICE, total_len, pktID, FRAGMENT_STATUS, TIME_TO_LIVE, PROTOCOL, check_sum_of_hdr, \
            src_IP, dest_IP = struct.unpack('!BBHHHBBH4s4s', self.l3_header)
        if PROTOCOL == 1:
            self.l4 = 'icmp'
        elif PROTOCOL == 6:
            self.l4 = 'tcp'
        elif PROTOCOL == 17:
            self.l4 = 'udp'
        else:
            self.l4 = 'others'

        self.l3_field = {
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

    def unpack_tcp_header(self) -> None:
        self.l4_header = self.packet[settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN: settings.ETH_HEADER_LEN +
                                     settings.IP_HEADER_LEN + settings.TCP_HEADER_LEN]
        padding = self.packet[settings.ETH_HEADER_LEN + self.l3_field['total_len']:]
        src_port, dest_port, seq, ack_num, offset, flags, window, checksum, urgent_ptr = struct.unpack(
            '!HHLLsBHHH', self.l4_header)
        tcp_len = int.from_bytes(offset, byteorder='big') >> 2

        self.l4_field = {
            'src_port': src_port,
            'dest_port': dest_port,
            'seq': seq,
            'ack_num': ack_num,
            'offset': offset,
            'flags': flags,
            'window': window,
            'checksum': checksum,
            'urgent_ptr': urgent_ptr,
            'padding': padding,
            'tcp_len': tcp_len,
            'tcp_option': self.packet[settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN + settings.TCP_HEADER_LEN:
                                      settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN + tcp_len],
            'payload': self.packet[settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN + tcp_len:
                                   settings.ETH_HEADER_LEN + self.l3_field['total_len']],
            'option_field': None,
            'kind_seq': []
        }

        if self.l4_field['tcp_option'] != b'':
            option_field, kind_seq = Packet.unpack_tcp_option(self.l4_field['tcp_option'])
            self.l4_field['option_field'] = option_field
            self.l4_field['kind_seq'] = kind_seq

    def unpack_udp_header(self) -> None:
        self.l4_header = self.packet[settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN: settings.ETH_HEADER_LEN +
                                     settings.IP_HEADER_LEN + settings.UDP_HEADER_LEN]
        data = self.packet[settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN + settings.UDP_HEADER_LEN:]
        src_port, dest_port, udp_len, checksum = struct.unpack('!4H', self.l4_header)

        self.l4_field = {
            'src_port': src_port,
            'dest_port': dest_port,
            'udp_len': udp_len,
            'checksum': checksum,
            'data': data
        }

    def unpack_icmp_header(self) -> None:
        self.l4_header = self.packet[settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN: settings.ETH_HEADER_LEN +
                                     settings.IP_HEADER_LEN + settings.ICMP_HEADER_LEN]
        data = self.packet[settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN + settings.ICMP_HEADER_LEN:]
        icmp_type, code, checksum, ID, seq = struct.unpack('BbHHh', self.l4_header)

        self.l4_field = {
            'icmp_type': icmp_type,
            'code': code,
            'checksum': checksum,
            'ID': ID,
            'seq': seq,
            'data': data
        }

    def pack(self) -> None:
        self.pack_l2_header()
        self.pack_l3_header()
        if self.l4 != '':
            self.pack_l4_header()

    def pack_l2_header(self):
        eth_field = self.l2_field

        if type(eth_field['dMAC']) == str:
            eth_field['dMAC'] = Packet.mac_str2byte(eth_field['dMAC'])
        if type(eth_field['sMAC']) == str:
            eth_field['sMAC'] = Packet.mac_str2byte(eth_field['sMAC'])

        self.l2_field['dMAC'] = eth_field['dMAC']
        self.l2_field['sMAC'] = eth_field['sMAC']
        # struct.pack's MAC arguments have to be bytes
        self.l2_header = struct.pack('!6s6sH', eth_field['dMAC'], eth_field['sMAC'], eth_field['protocol'])
        self.packet += self.l2_header

    def pack_l3_header(self):
        if self.l3 == 'ip':
            self.pack_ip_header()
        elif self.l3 == 'arp':
            self.pack_arp_header()
        self.packet += self.l3_header

    def pack_l4_header(self):
        if self.l4 == 'tcp':
            self.pack_tcp_header()
        elif self.l4 == 'udp':
            self.pack_udp_header()
        elif self.l4 == 'icmp':
            self.pack_icmp_header()
        self.packet += self.l4_header
        try:
            if self.l4_field['padding'] != '':
                if self.l4_field['padding'] == str:
                    self.l4_field['padding'] = Packet.padding_str2byte(self.l4_field['padding'])
                self.packet += self.l4_field['padding']
        except KeyError:
            pass

    def pack_arp_header(self):
        arp_field = self.l3_field
        self.l3_header = struct.pack('2s2s1s1s2s6s4s6s4s', arp_field['hw_type'], arp_field['proto_type'],
                                     arp_field['hw_size'], arp_field['proto_size'], arp_field['opcode'],
                                     arp_field['sender_mac'], arp_field['sender_ip'], arp_field['recv_mac'],
                                     arp_field['recv_ip'])

    def pack_ip_header(self):
        ip_field = self.l3_field
        if type(ip_field['src_IP']) and type(ip_field['dest_IP']) == str:
            ip_field['src_IP'] = Packet.ip_str2byte(ip_field['src_IP'])
            ip_field['dest_IP'] = Packet.ip_str2byte(ip_field['dest_IP'])
            self.l3_field['src_IP'] = ip_field['src_IP']
            self.l3_field['dest_IP'] = ip_field['dest_IP']

        pseudo_ip_header = struct.pack('!BBHHHBBH4s4s', ip_field['IHL_VERSION'], ip_field['TYPE_OF_SERVICE'],
                                       ip_field['total_len'], ip_field['pktID'], ip_field['FRAGMENT_STATUS'],
                                       ip_field['TIME_TO_LIVE'], ip_field['PROTOCOL'], 0,
                                       ip_field['src_IP'], ip_field['dest_IP'])
        ip_field['check_sum_of_hdr'] = Packet.getIPChecksum(pseudo_ip_header)
        self.l3_field['check_sum_of_hdr'] = ip_field['check_sum_of_hdr']
        self.l3_header = struct.pack('!BBHHHBBH4s4s', ip_field['IHL_VERSION'], ip_field['TYPE_OF_SERVICE'],
                                     ip_field['total_len'], ip_field['pktID'], ip_field['FRAGMENT_STATUS'],
                                     ip_field['TIME_TO_LIVE'], ip_field['PROTOCOL'], ip_field['check_sum_of_hdr'],
                                     ip_field['src_IP'], ip_field['dest_IP'])

    def pack_tcp_header(self):
        ip_field = self.l3_field
        tcp_field = self.l4_field
        tcp_option = Packet.pack_tcp_option(tcp_field['option_field'], tcp_field['kind_seq'])
        tcp_len = settings.TCP_HEADER_LEN + len(tcp_option)
        # offset = (tcp_len // 4) << 4

        # Calculate tcp checksum
        offset = tcp_len * 4
        tcp_header = struct.pack('!HHIIBBHHH', tcp_field['src_port'], tcp_field['dest_port'], tcp_field['seq'],
                                 tcp_field['ack_num'], offset, tcp_field['flags'], tcp_field['window'], 0,
                                 tcp_field['urgent_ptr'])
        tcp_header_with_option = tcp_header + tcp_option

        pseudo_hdr = struct.pack('!4s4sBBH', ip_field['src_IP'], ip_field['dest_IP'], 0, socket.IPPROTO_TCP,
                                 len(tcp_header_with_option))
        tcp_field['checksum'] = Packet.getTCPChecksum(pseudo_hdr + tcp_header_with_option)
        self.l4_field['tcp_option'] = tcp_option
        self.l4_field['checksum'] = tcp_field['checksum']
        self.l4_header = tcp_header_with_option[:16] + struct.pack('H', tcp_field['checksum']) + tcp_header_with_option[
                                                                                                 18:]

    def pack_udp_header(self):

        ip_field = self.l3_field
        udp_field = self.l4_field

        # Check the type of data
        encoded_data = ''
        try:
            encoded_data = self.data.encode()
        except AttributeError:
            pass

        # Calculate udp checksum
        udp_len = settings.UDP_HEADER_LEN + len(encoded_data)
        pseudo_header = struct.pack('!BBH', 0, socket.IPPROTO_UDP, udp_len)
        pseudo_header = ip_field['src_IP'] + ip_field['dest_IP'] + pseudo_header
        udp_header = struct.pack('!4H', udp_field['src_port'], udp_field['dest_port'], udp_field['udp_len'], 0)
        udp_field['checksum'] = Packet.getUDPChecksum(pseudo_header + udp_header + encoded_data)

        self.l4_field['checksum'] = udp_field['checksum']
        self.l4_header = struct.pack('!4H', udp_field['src_port'], udp_field['dest_port'], udp_field['udp_length'],
                                     udp_field['checksum'])

    def pack_icmp_header(self):
        icmp_field = self.l4_field
        checksum = 0
        pseudo_packet = struct.pack('BbHHh', icmp_field['icmp_type'], icmp_field['code'], checksum, icmp_field['ID'],
                                    icmp_field['seq']) + icmp_field['data']
        checksum = Packet.getTCPChecksum(pseudo_packet)
        icmp_header = struct.pack('BbHHh', icmp_field['icmp_type'], icmp_field['code'], checksum, icmp_field['ID'],
                                  icmp_field['seq']) + icmp_field['data']

        self.l4_field['checksum'] = checksum
        self.l4_header = icmp_header

    def get_proc(self):
        return self.l3 if self.l4 == '' else self.l4

    @staticmethod
    def diff_tcp(pkt1, pkt2):
        diff = {}
        eth_field_1, eth_field_2 = pkt1.l2_field, pkt2.l2_field
        ip_field_1, ip_field_2 = pkt1.l3_field, pkt2.l3_field
        tcp_field_1, tcp_field_2 = pkt1.l4_field, pkt2.l4_field

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

    @staticmethod
    def getIPChecksum(data):
        packet_sum = 0
        for index in range(0, len(data), 2):
            word = (data[index] << 8) + (data[index + 1])
            packet_sum = packet_sum + word
        packet_sum = (packet_sum >> 16) + (packet_sum & 0xffff)
        packet_sum = ~packet_sum & 0xffff
        return packet_sum

    @staticmethod
    def getTCPChecksum(packet):
        import array
        if len(packet) % 2 != 0:
            packet += b'\0'

        res = sum(array.array("H", packet))
        res = (res >> 16) + (res & 0xffff)
        res += res >> 16

        return (~res) & 0xffff

    @staticmethod
    def getUDPChecksum(data):
        checksum = 0
        data_len = len(data)
        if data_len % 2:
            data_len += 1
            data += struct.pack('!B', 0)

        for i in range(0, data_len, 2):
            w = (data[i] << 8) + (data[i + 1])
            checksum += w

        checksum = (checksum >> 16) + (checksum & 0xFFFF)
        checksum = ~checksum & 0xFFFF
        return checksum

    @staticmethod
    def pack_tcp_option(option_val, kind_seq):
        import time
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

    @staticmethod
    def unpack_tcp_option(tcp_option):
        start_ptr = 0
        kind_seq = []
        option_val = {
            'padding': [],
            'mss': None,
            'shift_count': None,
            'sack_permitted': None,
            'ts_val': None,
            'ts_echo_reply': None,
            'kind_seq': None
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
                option_val['ts_val'], option_val['ts_echo_reply'] = struct.unpack('!LL', tcp_option[start_ptr:start_ptr + length - 2])
                start_ptr += length - 2
                kind_seq.append(kind)

            option_val['kind_seq'] = kind_seq

        return option_val, kind_seq

    @staticmethod
    def ip_str2byte(ip_str: str):
        if ip_str == 'localhost':
            ip_str = '127.0.0.1'
        ip_int = [int(x) for x in ip_str.split('.')]

        return struct.pack('!4B', *ip_int)

    @staticmethod
    def mac_byte2str(mac_byte):
        mac_str = "%02x:%02x:%02x:%02x:%02x:%02x" % struct.unpack("BBBBBB", mac_byte)

        return mac_str

    @staticmethod
    def mac_str2byte(mac_str):
        print(f'input mac: {mac_str}')
        mac_byte = b''
        for x in mac_str.split(':'):
            mac_byte += bytes.fromhex(x)

        return mac_byte

    @staticmethod
    def padding_str2byte(padding_str: str):
        """
        '0000' --> b'\x00\x00'
        """
        return bytes.fromhex(padding_str)


