import socket
import struct
import src.settings as settings

from src.tcp import TcpConnect, getIPChecksum, unpack_tcp_option, pack_tcp_option, os_build_tcp_header_from_reply


class OsDeceiver:

    def __init__(self, host):
        self.host = host
        self.conn = TcpConnect(host)

    def os_record(self):
        pkt_dict = {}
        port_pair_seq = []
        key_seq = []  # prevent IndexError cuz dict.keys() would ignore same keys
        count = 1
        while True:
            packet, _ = self.conn.sock.recvfrom(65565)
            eth_header = packet[: settings.ETH_HEADER_LEN]
            eth = struct.unpack('!6s6sH', eth_header)
            eth_protocol = socket.ntohs(eth[2])

            if eth_protocol != 8:
                continue

            ip_header = packet[settings.ETH_HEADER_LEN: settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN]
            _, _, _, _, _, _, PROTOCOL, _, src_IP, dest_IP = struct.unpack('!BBHHHBBH4s4s', ip_header)

            # tcp=6
            if PROTOCOL == 6:
                tcp_header = packet[settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN: settings.ETH_HEADER_LEN
                                                            + settings.IP_HEADER_LEN + settings.TCP_HEADER_LEN]
                src_port, dest_port, seq, ack_num, offset, flags, window, checksum, urgent_ptr = struct.unpack(
                    '!HHLLBBHHH', tcp_header)

                # store pkt as key
                if dest_IP == socket.inet_aton(self.host):
                    key, packet_val = generate_key(packet)
                    if packet_val['flags'] == 4:
                        continue
                    port_pair_seq.append((src_port, dest_port))
                    key_seq.append(key)
                    if key not in pkt_dict.keys():
                        pkt_dict[key] = None

                elif src_IP == socket.inet_aton(self.host) and (dest_port, src_port) in port_pair_seq:
                    pkt_index = port_pair_seq.index((dest_port, src_port))
                    key = key_seq[pkt_index]
                    if pkt_dict[key] is None:   # assume same packet format received would have same replied format??
                        print('add %d reply' % count)
                        count += 1
                        pkt_dict[key] = packet

                else:
                    continue

                f = open('pkt_record.txt', 'w')
                f.write(str(pkt_dict))

            else:
                continue

    def os_deceive(self):
        os_file = open('pkt_record.txt', 'r')
        pkt_dict = eval(os_file.readline())
        pkt_dict = {k: v for (k, v) in pkt_dict.items() if v is not None}
        print('[!] loaded pcap file for packet reply...')

        while True:
            packet, _ = self.conn.sock.recvfrom(65565)
            eth_header = packet[: settings.ETH_HEADER_LEN]
            eth = struct.unpack('!6s6sH', eth_header)
            eth_protocol = socket.ntohs(eth[2])

            if eth_protocol != 8:
                continue

            ip_header = packet[settings.ETH_HEADER_LEN: settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN]
            _, _, total_len, _, _, _, PROTOCOL, _, src_IP, dest_IP = struct.unpack('!BBHHHBBH4s4s', ip_header)

            if dest_IP != socket.inet_aton(self.host):
                continue

            # tcp=6
            if PROTOCOL == 6:
                key, pkt_info = generate_key(packet)
                tcp_header = pkt_info['tcp_header']
                tcp_option = pkt_info['tcp_option']
                _, recv_kind_seq = unpack_tcp_option(tcp_option)

                # received 'RST', don't reply
                if pkt_info['flags'] == 4:
                    continue

                try:
                    reply_packet = pkt_dict[key]
                except KeyError:
                    continue

                reply_eth_header = reply_packet[: settings.ETH_HEADER_LEN]
                reply_ip_header = reply_packet[settings.ETH_HEADER_LEN: settings.ETH_HEADER_LEN +
                                               settings.IP_HEADER_LEN]
                reply_tcp_header = reply_packet[settings.ETH_HEADER_LEN +
                                                settings.IP_HEADER_LEN: settings.ETH_HEADER_LEN +
                                                settings.IP_HEADER_LEN + settings.TCP_HEADER_LEN]
                reply_tcp_option = reply_packet[settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN +
                                                settings.TCP_HEADER_LEN:]
                IHL_VERSION, TYPE_OF_SERVICE, total_len, pktID, FRAGMENT_STATUS, TIME_TO_LIVE, PROTOCOL, \
                    check_sum_of_hdr, reply_src_IP, reply_dest_IP = struct.unpack('!BBHHHBBH4s4s', reply_ip_header)
                reply_src_IP = dest_IP
                reply_dest_IP = src_IP

                if len(reply_tcp_option) == 0:
                    total_len = 40

                else:
                    total_len = len(reply_ip_header) + len(reply_tcp_header) + len(reply_tcp_option)
                    option_val, kind_seq = unpack_tcp_option(reply_tcp_option)
                    if 8 in recv_kind_seq:
                        ts_val = unpack_tcp_option(tcp_option)[0]['ts_val']    # record packet's ts_val
                        option_val['ts_echo_reply'] = ts_val
                    reply_tcp_option = pack_tcp_option(option_val, kind_seq)

                check_sum_of_hdr = 0
                reply_ip_header = struct.pack('!BBHHHBBH4s4s', IHL_VERSION, TYPE_OF_SERVICE, total_len, pktID,
                                              FRAGMENT_STATUS, TIME_TO_LIVE, PROTOCOL, check_sum_of_hdr,
                                              reply_src_IP, reply_dest_IP)
                check_sum_of_hdr = getIPChecksum(reply_ip_header)
                reply_ip_header = struct.pack('!BBHHHBBH4s4s', IHL_VERSION, TYPE_OF_SERVICE, total_len, pktID,
                                              FRAGMENT_STATUS, TIME_TO_LIVE, PROTOCOL, check_sum_of_hdr,
                                              reply_src_IP, reply_dest_IP)
                reply_src_port, reply_dest_port, reply_seq, reply_ack_num, offset, reply_flags, reply_window, \
                    checksum, urgent_ptr = struct.unpack('!HHLLBBHHH', reply_tcp_header)

                reply_src_port = pkt_info['dest_port']
                reply_dest_port = pkt_info['src_port']
                reply_seq = pkt_info['ack_num']
                reply_ack_num = pkt_info['seq'] + 1
                tcp_len = (len(reply_tcp_header) + len(reply_tcp_option)) // 4
                reply_tcp_header_option = os_build_tcp_header_from_reply(tcp_len, reply_seq, reply_ack_num,
                                                                         reply_src_port, reply_dest_port,
                                                                         reply_src_IP, reply_dest_IP, reply_flags,
                                                                         reply_window, reply_tcp_option)

                packet = reply_eth_header + reply_ip_header + reply_tcp_header_option
                self.conn.sock.send(packet)
                print('*' * 20, '\n', 'send 1 packet', '\n', '*'*20)
                continue

            else:
                continue


def generate_key(packet: bytes):
    # store original field value to specify key-value pair
    packet_val = {
        'src_IP': None,
        'dest_IP': None,
        'src_port': None,
        'dest_port': None,
        'seq': None,
        'ack_num': None,
        'flags': None,
        'ip_header': packet[settings.ETH_HEADER_LEN: settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN],
        'tcp_header': packet[settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN: settings.ETH_HEADER_LEN +
                             settings.IP_HEADER_LEN + settings.TCP_HEADER_LEN],
        'tcp_option': packet[settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN + settings.TCP_HEADER_LEN:]
    }

    ip_header = packet_val['ip_header']
    tcp_header = packet_val['tcp_header']
    tcp_option = packet_val['tcp_option']

    # handle ip header
    IHL_VERSION, TYPE_OF_SERVICE, total_len, pktID, FRAGMENT_STATUS, ttl, PROTOCOL, check_sum_of_hdr, src_IP, dest_IP =\
        struct.unpack('!BBHHHBBH4s4s', ip_header)
    packet_val['src_IP'], packet_val['dest_IP'] = src_IP, dest_IP
    pktID, ttl, check_sum_of_hdr, src_IP, dest_IP = 0, 0, 0, b'\x00\x00\x00\x00', b'\x00\x00\x00\x00'
    ip_header = struct.pack('!BBHHHBBH4s4s', IHL_VERSION, TYPE_OF_SERVICE, total_len, pktID, FRAGMENT_STATUS, ttl,
                            PROTOCOL, check_sum_of_hdr, src_IP, dest_IP)

    # handle tcp header
    src_port, dest_port, seq, ack_num, offset, flags, window, checksum, urgent_ptr = struct.unpack('!HHLLBBHHH',
                                                                                                   tcp_header)
    packet_val['src_port'], packet_val['dest_port'], packet_val['flags'] = src_port, dest_port, flags
    packet_val['seq'], packet_val['ack_num'] = seq, ack_num
    src_port, seq, ack_num, checksum = 0, 0, 0, 0
    tcp_header = struct.pack('!HHLLBBHHH', src_port, dest_port, seq, ack_num, offset, flags, window, checksum,
                             urgent_ptr)

    # reserve original tcp option
    packet_key = ip_header + tcp_header + tcp_option

    return packet_key, packet_val
