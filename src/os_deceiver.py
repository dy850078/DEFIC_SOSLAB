import logging
import socket
import struct
import src.settings as settings
from src.Packet import Packet
from src.tcp import TcpConnect, getIPChecksum, unpack_tcp_option, pack_tcp_option, os_build_tcp_header_from_reply, \
    getTCPChecksum


class OsDeceiver:

    def __init__(self, host):
        self.host = host
        self.conn = TcpConnect(host)

    def os_record(self):
        arp_pkt_dict = {}
        ip_pair_seq = []
        arp_key_seq = []

        udp_pkt_dict = {}

        icmp_pkt_dict = {}
        id_pair_seq = []
        icmp_key_seq = []

        pkt_dict = {}
        port_pair_seq = []
        key_seq = []  # prevent IndexError cuz dict.keys() would ignore same keys

        count = 1
        while True:
            packet, _ = self.conn.sock.recvfrom(65565)
            eth_header = packet[: settings.ETH_HEADER_LEN]
            eth = struct.unpack('!6s6sH', eth_header)
            eth_protocol = socket.ntohs(eth[2])

            # ip=8
            if eth_protocol == 8:
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
                        key, packet_val = gen_tcp_key(packet)
                        if packet_val['flags'] == 4:
                            continue
                        port_pair_seq.append((src_port, dest_port))
                        key_seq.append(key)
                        if key not in pkt_dict.keys():
                            pkt_dict[key] = None

                    # store response pkt as value qqqqq
                    elif src_IP == socket.inet_aton(self.host) and (dest_port, src_port) in port_pair_seq:
                        pkt_index = port_pair_seq.index((dest_port, src_port))
                        key = key_seq[pkt_index]
                        if pkt_dict[key] is None:  # assume same packet format received would have same replied format??
                            print('add %d reply' % count)
                            count += 1
                            pkt_dict[key] = packet

                    else:
                        continue

                    f = open('tcp_record.txt', 'w')
                    f.write(str(pkt_dict))
                    f.close()

                # icmp=1
                elif PROTOCOL == 1:
                    icmp_header = packet[settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN: settings.ETH_HEADER_LEN +
                                         settings.IP_HEADER_LEN + settings.ICMP_HEADER_LEN]
                    partial_data = packet[: settings.ETH_HEADER_LEN] + packet[settings.ETH_HEADER_LEN +
                                                                              settings.IP_HEADER_LEN +
                                                                              settings.ICMP_HEADER_LEN:]
                    # data = packet[settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN + settings.ICMP_HEADER_LEN:]
                    icmp_type, code, checksum, ID, seq = struct.unpack('BbHHh', icmp_header)

                    # store pkt as key
                    if dest_IP == socket.inet_aton(self.host):
                        key, packet_val = gen_icmp_key(packet)
                        id_pair_seq.append(ID)
                        icmp_key_seq.append(key)
                        if key not in icmp_pkt_dict.keys():
                            icmp_pkt_dict[key] = None

                    # store response pkt as value
                    elif src_IP == socket.inet_aton(self.host):
                        if ID in id_pair_seq:
                            pkt_index = id_pair_seq.index(ID)
                            key = icmp_key_seq[pkt_index]
                            icmp_pkt_dict[key] = packet

                        elif icmp_type == 3:
                            key, packet_val = gen_udp_key(partial_data)
                            if key in udp_pkt_dict:
                                udp_pkt_dict[key] = packet
                            f = open('udp_record.txt', 'w')
                            f.write(str(udp_pkt_dict))
                            f.close()
                            continue

                    else:
                        continue

                    f = open('icmp_record.txt', 'w')
                    f.write(str(icmp_pkt_dict))
                    f.close()

                # udp=17
                elif PROTOCOL == 17:
                    # store pkt as key
                    if dest_IP == socket.inet_aton(self.host):
                        key, packet_val = gen_udp_key(packet)
                        if key not in udp_pkt_dict.keys():
                            udp_pkt_dict[key] = None
                    else:
                        continue

                    f = open('udp_record.txt', 'w')
                    f.write(str(udp_pkt_dict))
                    f.close()

                else:
                    continue

            # arp=1544
            elif eth_protocol == 1544:
                arp_header = packet[settings.ETH_HEADER_LEN: settings.ETH_HEADER_LEN + settings.ARP_HEADER_LEN]
                hw_type, proto_type, hw_size, proto_size, opcode, sender_mac, sender_ip, recv_mac, recv_ip = \
                    struct.unpack('2s2s1s1s2s6s4s6s4s', arp_header)

                if recv_ip == socket.inet_aton(self.host):
                    key, packet_val = gen_arp_key(packet)
                    ip_pair_seq.append((sender_ip, recv_ip))
                    arp_key_seq.append(key)
                    if key not in arp_pkt_dict.keys():
                        arp_pkt_dict[key] = None

                elif sender_ip == socket.inet_aton(self.host) and (recv_ip, sender_ip) in ip_pair_seq:
                    pkt_index = ip_pair_seq.index((recv_ip, sender_ip))
                    key = arp_key_seq[pkt_index]
                    arp_pkt_dict[key] = packet

                else:
                    continue

                f = open('arp_record.txt', 'w')
                f.write(str(arp_pkt_dict))
                f.close()

            else:
                continue

    def os_deceive(self):
        logging.basicConfig(level=logging.INFO)

        # load packet reference
        arp_packet_dict = load_pkt_file('arp')
        packet_dict = load_pkt_file('tcp')
        udp_packet_dict = load_pkt_file('udp')
        icmp_packet_dict = load_pkt_file('icmp')

        while True:
            packet, _ = self.conn.sock.recvfrom(65565)
            eth_header = packet[: settings.ETH_HEADER_LEN]
            eth = struct.unpack('!6s6sH', eth_header)
            eth_dMAC = eth[0]
            eth_sMAC = eth[1]
            eth_protocol = socket.ntohs(eth[2])

            # ip=8
            if eth_protocol == 8:
                reply_eth_dMAC = eth_sMAC
                reply_eth_sMAC = eth_dMAC
                reply_eth_header = struct.pack('!6s6sH', reply_eth_dMAC, reply_eth_sMAC, eth[2])
                ip_header = packet[settings.ETH_HEADER_LEN: settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN]
                _, _, total_len, _, _, _, PROTOCOL, _, src_IP, dest_IP = struct.unpack('!BBHHHBBH4s4s', ip_header)

                if dest_IP != socket.inet_aton(self.host):
                    continue

                # tcp=6
                if PROTOCOL == 6:
                    key, pkt_info = gen_tcp_key(packet)
                    tcp_option = pkt_info['tcp_option']
                    _, recv_kind_seq = unpack_tcp_option(tcp_option)

                    # received 'RST', don't reply
                    if pkt_info['flags'] == 4:
                        continue

                    try:
                        reply_packet = packet_dict[key]
                    except KeyError:
                        continue

                    # reply_eth_header = reply_packet[: settings.ETH_HEADER_LEN]
                    reply_ip_header = reply_packet[settings.ETH_HEADER_LEN: settings.ETH_HEADER_LEN +
                                                   settings.IP_HEADER_LEN]
                    reply_tcp_header = reply_packet[settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN:
                                                    settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN +
                                                    settings.TCP_HEADER_LEN]

                    IHL_VERSION, TYPE_OF_SERVICE, total_len, pktID, FRAGMENT_STATUS, TIME_TO_LIVE, PROTOCOL, \
                        check_sum_of_hdr, reply_src_IP, reply_dest_IP = struct.unpack('!BBHHHBBH4s4s', reply_ip_header)

                    reply_src_IP = dest_IP
                    reply_dest_IP = src_IP

                    reply_tcp_option = reply_packet[settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN +
                                                    settings.TCP_HEADER_LEN: settings.ETH_HEADER_LEN + total_len]
                    reply_padding = reply_packet[settings.ETH_HEADER_LEN + total_len:]
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
                    if pkt_info['flags'] == 0:
                        reply_ack_num = pkt_info['seq']
                    elif pkt_info['flags'] == 43:
                        reply_ack_num = pkt_info['seq'] + 2
                    else:
                        reply_ack_num = pkt_info['seq'] + 1
                    tcp_len = (len(reply_tcp_header) + len(reply_tcp_option)) // 4
                    reply_tcp_header_option = os_build_tcp_header_from_reply(tcp_len, reply_seq, reply_ack_num,
                                                                             reply_src_port, reply_dest_port,
                                                                             reply_src_IP, reply_dest_IP, reply_flags,
                                                                             reply_window, reply_tcp_option)

                    packet = reply_eth_header + reply_ip_header + reply_tcp_header_option + reply_padding
                    self.conn.sock.send(packet)
                    print('*' * 20, '\n', 'send 1 packet', '\n', '*'*20)
                    continue

                # icmp=1
                elif PROTOCOL == 1:
                    key, pkt_info = gen_icmp_key(packet)

                    try:
                        reply_packet = icmp_packet_dict[key]
                    except KeyError:
                        continue

                    reply_ip_header = reply_packet[settings.ETH_HEADER_LEN: settings.ETH_HEADER_LEN +
                                                   settings.IP_HEADER_LEN]
                    reply_icmp_header = reply_packet[settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN:
                                                     settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN +
                                                     settings.ICMP_HEADER_LEN]
                    reply_data = reply_packet[settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN + settings.ICMP_HEADER_LEN:]

                    IHL_VERSION, TYPE_OF_SERVICE, total_len, pktID, FRAGMENT_STATUS, TIME_TO_LIVE, PROTOCOL, \
                        check_sum_of_hdr, reply_src_IP, reply_dest_IP = struct.unpack('!BBHHHBBH4s4s', reply_ip_header)

                    # replace ip field and compute checksum
                    # arbitrary number but maybe this random value generation is critical to os fingerprint
                    pktID = 456
                    reply_src_IP = dest_IP
                    reply_dest_IP = src_IP
                    check_sum_of_hdr = 0
                    reply_ip_header = struct.pack('!BBHHHBBH4s4s', IHL_VERSION, TYPE_OF_SERVICE, total_len, pktID,
                                                  FRAGMENT_STATUS,
                                                  TIME_TO_LIVE, PROTOCOL, check_sum_of_hdr, reply_src_IP, reply_dest_IP)
                    check_sum_of_hdr = getIPChecksum(reply_ip_header)
                    reply_ip_header = struct.pack('!BBHHHBBH4s4s', IHL_VERSION, TYPE_OF_SERVICE, total_len, pktID,
                                                  FRAGMENT_STATUS,
                                                  TIME_TO_LIVE, PROTOCOL, check_sum_of_hdr, reply_src_IP, reply_dest_IP)

                    icmp_type, code, checksum, ID, seq = struct.unpack('BbHHh', reply_icmp_header)
                    ID = pkt_info['ID']
                    seq = pkt_info['seq']
                    checksum = 0
                    pseudo_packet = struct.pack('BbHHh', icmp_type, code, checksum, ID, seq) + reply_data
                    checksum = getTCPChecksum(pseudo_packet)
                    reply_icmp_header = struct.pack('BbHHh', icmp_type, code, checksum, ID, seq)
                    packet = reply_eth_header + reply_ip_header + reply_icmp_header + reply_data
                    self.conn.sock.send(packet)
                    print('\n', '*' * 20, '\n', 'send 1  icmp packet', '\n', '*' * 20)
                    continue

                # udp=17
                elif PROTOCOL == 17:
                    key, pkt_info = gen_udp_key(packet)
                    try:
                        reply_packet = udp_packet_dict[key]
                    except KeyError:
                        continue
                    reply_ip_header = reply_packet[settings.ETH_HEADER_LEN: settings.ETH_HEADER_LEN +
                                                   settings.IP_HEADER_LEN]
                    reply_icmp_header = reply_packet[settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN:
                                                     settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN +
                                                     settings.ICMP_HEADER_LEN]
                    # the icmp packet for udp pkt reply contain a part of udp packet after all its fields
                    reply_data = packet[settings.ETH_HEADER_LEN:]

                    IHL_VERSION, TYPE_OF_SERVICE, total_len, pktID, FRAGMENT_STATUS, TIME_TO_LIVE, PROTOCOL, \
                        check_sum_of_hdr, reply_src_IP, reply_dest_IP = struct.unpack('!BBHHHBBH4s4s', reply_ip_header)

                    # replace ip field and compute checksum
                    # arbitrary number but maybe this random value generation is critical to os fingerprint
                    pktID = 456
                    reply_src_IP = dest_IP
                    reply_dest_IP = src_IP
                    check_sum_of_hdr = 0
                    reply_ip_header = struct.pack('!BBHHHBBH4s4s', IHL_VERSION, TYPE_OF_SERVICE, total_len, pktID,
                                                  FRAGMENT_STATUS,
                                                  TIME_TO_LIVE, PROTOCOL, check_sum_of_hdr, reply_src_IP, reply_dest_IP)
                    check_sum_of_hdr = getIPChecksum(reply_ip_header)
                    reply_ip_header = struct.pack('!BBHHHBBH4s4s', IHL_VERSION, TYPE_OF_SERVICE, total_len, pktID,
                                                  FRAGMENT_STATUS,
                                                  TIME_TO_LIVE, PROTOCOL, check_sum_of_hdr, reply_src_IP, reply_dest_IP)

                    icmp_type, code, checksum, ID, seq = struct.unpack('BbHHh', reply_icmp_header)
                    ID = 0
                    seq = 0
                    checksum = 0
                    pseudo_packet = struct.pack('BbHHh', icmp_type, code, checksum, ID, seq) + reply_data
                    checksum = getTCPChecksum(pseudo_packet)
                    reply_icmp_header = struct.pack('BbHHh', icmp_type, code, checksum, ID, seq)
                    packet = reply_eth_header + reply_ip_header + reply_icmp_header + reply_data
                    self.conn.sock.send(packet)
                    print('\n', '*' * 20, '\n', 'send 1  icmp(udp) packet', '\n', '*' * 20)
                    continue

            # arp=1544
            elif eth_protocol == 1544:
                arp_header = packet[settings.ETH_HEADER_LEN: settings.ETH_HEADER_LEN + settings.ARP_HEADER_LEN]
                _, _, _, _, _, sender_mac, sender_ip, recv_mac, recv_ip = \
                    struct.unpack('2s2s1s1s2s6s4s6s4s', arp_header)

                if recv_ip != socket.inet_aton(self.host):
                    continue

                key, pkt_info = gen_arp_key(packet)
                try:
                    reply_packet = arp_packet_dict[key]
                except KeyError:
                    continue
                # reply eth header
                reply_eth_dMAC = eth_sMAC
                reply_eth_sMAC = settings.mac
                reply_eth_header = struct.pack('!6s6sH', reply_eth_dMAC, reply_eth_sMAC, eth[2])
                reply_arp_header = reply_packet[settings.ETH_HEADER_LEN: settings.ETH_HEADER_LEN +
                                                settings.ARP_HEADER_LEN]

                # reply padding
                reply_padding = reply_packet[settings.ETH_HEADER_LEN + settings.ARP_HEADER_LEN:]

                # reply arp header
                hw_type, proto_type, hw_size, proto_size, opcode, _, _, _, _ = struct.unpack('2s2s1s1s2s6s4s6s4s',
                                                                                             reply_arp_header)
                reply_sender_mac = settings.mac
                reply_sender_ip = socket.inet_aton(self.host)
                reply_recv_mac = sender_mac
                reply_recv_ip = sender_ip
                reply_arp_header = struct.pack('2s2s1s1s2s6s4s6s4s', hw_type, proto_type, hw_size, proto_size, opcode,
                                               reply_sender_mac, reply_sender_ip, reply_recv_mac, reply_recv_ip)

                packet = reply_eth_header + reply_arp_header + reply_padding
                self.conn.sock.send(packet)
                print('\n', '*' * 20, '\n', 'send 1  arp packet', '\n', '*'*20)
            else:
                continue

    def store_rsp(self):
        rsp = {}
        while True:
            packet, _ = self.conn.sock.recvfrom(65565)
            eth_header = packet[: settings.ETH_HEADER_LEN]
            eth = struct.unpack('!6s6sH', eth_header)
            eth_protocol = socket.ntohs(eth[2])

            if eth_protocol == 8:
                ip_header = packet[settings.ETH_HEADER_LEN: settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN]
                _, _, _, _, _, _, PROTOCOL, _, src_IP, dest_IP = struct.unpack('!BBHHHBBH4s4s', ip_header)

                # tcp=6
                if PROTOCOL == 6 and src_IP == socket.inet_aton(self.host):
                    pkt = Packet(packet)
                    src_port = pkt.tcp_field['src_port']
                    if src_port not in rsp:
                        rsp[src_port] = []
                    rsp[src_port].append(packet)

                    f = open('rsp_record.txt', 'w')
                    f.write(str(rsp))
                    f.close()
            continue


def load_pkt_file(pkt_type: str):
    logging.basicConfig(level=logging.INFO)
    file = open('%s_record.txt' % pkt_type, 'r')
    packet_dict = eval(file.readline())
    clean_packet_dict = {k: v for (k, v) in packet_dict.items() if v is not None}
    logging.info('%s pcap file is loaded' % pkt_type)

    return clean_packet_dict


def gen_tcp_key(packet: bytes):
    # store original field value to specify key-value pair
    packet_val = {
        'src_IP': None,
        'dest_IP': None,
        'src_port': None,
        'dest_port': None,
        'seq': None,
        'ack_num': None,
        'flags': None,
        'tcp_len': None,
        'ip_header': packet[settings.ETH_HEADER_LEN: settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN],
        'tcp_header': packet[settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN: settings.ETH_HEADER_LEN +
                             settings.IP_HEADER_LEN + settings.TCP_HEADER_LEN],
        'tcp_option': None,
        'padding': None
    }

    ip_header = packet_val['ip_header']
    tcp_header = packet_val['tcp_header']

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
    packet_val['seq'], packet_val['ack_num'], packet_val['tcp_len'] = seq, ack_num, offset // 4
    packet_val['tcp_option'] = packet[settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN + settings.TCP_HEADER_LEN:
                                      settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN + settings.TCP_HEADER_LEN +
                                      packet_val['tcp_len']]
    packet_val['padding'] = packet[settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN + settings.TCP_HEADER_LEN +
                                   packet_val['tcp_len']:]
    tcp_option = packet_val['tcp_option']
    padding = packet_val['padding']

    src_port, seq, ack_num, checksum = 0, 0, 0, 0
    tcp_header = struct.pack('!HHLLBBHHH', src_port, dest_port, seq, ack_num, offset, flags, window, checksum,
                             urgent_ptr)

    # reserve original tcp option

    packet_key = ip_header + tcp_header + tcp_option + padding

    return packet_key, packet_val


def gen_icmp_key(packet: bytes):
    packet_val = {
        'src_IP': None,
        'dest_IP': None,
        'icmp_type': None,
        'code': None,
        'ID': None,
        'seq': None,
        'ip_header': packet[settings.ETH_HEADER_LEN: settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN],
        'icmp_header': packet[settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN: settings.ETH_HEADER_LEN +
                              settings.IP_HEADER_LEN + settings.ICMP_HEADER_LEN]
    }

    ip_header = packet_val['ip_header']
    icmp_header = packet_val['icmp_header']

    # handle ip header
    IHL_VERSION, TYPE_OF_SERVICE, total_len, pktID, FRAGMENT_STATUS, ttl, PROTOCOL, check_sum_of_hdr, src_IP, dest_IP =\
        struct.unpack('!BBHHHBBH4s4s', ip_header)
    packet_val['src_IP'], packet_val['dest_IP'] = src_IP, dest_IP
    pktID, ttl, check_sum_of_hdr, src_IP, dest_IP = 0, 0, 0, b'\x00\x00\x00\x00', b'\x00\x00\x00\x00'
    ip_header = struct.pack('!BBHHHBBH4s4s', IHL_VERSION, TYPE_OF_SERVICE, total_len, pktID, FRAGMENT_STATUS, ttl,
                            PROTOCOL, check_sum_of_hdr, src_IP, dest_IP)

    # handle icmp header
    icmp_type, code, checksum, ID, seq = struct.unpack('BbHHh', icmp_header)

    # wondering if 'code' field can be ignored
    packet_val['icmp_type'], packet_val['code'], packet_val['ID'], packet_val['seq'] = icmp_type, code, ID, seq
    checksum, ID, seq = 0, 0, 0
    icmp_header = struct.pack('BbHHh', icmp_type, code, checksum, ID, seq)

    packet_key = ip_header + icmp_header

    return packet_key, packet_val


def gen_arp_key(packet: bytes):
    arp_header = packet[settings.ETH_HEADER_LEN: settings.ETH_HEADER_LEN + settings.ARP_HEADER_LEN]
    padding = packet[settings.ETH_HEADER_LEN + settings.ARP_HEADER_LEN:]
    hw_type, proto_type, hw_size, proto_size, opcode, sender_mac, sender_ip, recv_mac, recv_ip = struct.unpack(
        '2s2s1s1s2s6s4s6s4s', arp_header)
    packet_val = {
        'opcode': opcode,
        'sender_mac': sender_mac,
        'sender_ip': sender_ip,
        'recv_mac': recv_mac,
        'recv_ip': recv_ip
    }
    sender_mac, sender_ip, recv_mac, recv_ip = b'\x00\x00\x00\x00\x00\x00', b'\x00\x00\x00\x00', \
                                               b'\x00\x00\x00\x00\x00\x00', b'\x00\x00\x00\x00'
    arp_header = struct.pack('2s2s1s1s2s6s4s6s4s', hw_type, proto_type, hw_size, proto_size, opcode, sender_mac,
                             sender_ip, recv_mac, recv_ip)
    packet_key = arp_header + padding

    return packet_key, packet_val


def gen_udp_key(packet: bytes):
    # handle ip header
    ip_header = packet[settings.ETH_HEADER_LEN: settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN]
    IHL_VERSION, TYPE_OF_SERVICE, total_len, pktID, FRAGMENT_STATUS, ttl, PROTOCOL, check_sum_of_hdr, src_IP, dest_IP =\
        struct.unpack('!BBHHHBBH4s4s', ip_header)
    ttl, check_sum_of_hdr, src_IP, dest_IP = 0, 0, b'\x00\x00\x00\x00', b'\x00\x00\x00\x00'  # remove pktID=0 initialize
    ip_header = struct.pack('!BBHHHBBH4s4s', IHL_VERSION, TYPE_OF_SERVICE, total_len, pktID, FRAGMENT_STATUS, ttl,
                            PROTOCOL, check_sum_of_hdr, src_IP, dest_IP)

    # handle udp header
    udp_header = packet[settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN: settings.ETH_HEADER_LEN +
                        settings.IP_HEADER_LEN + settings.UDP_HEADER_LEN]
    data = packet[settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN + settings.UDP_HEADER_LEN:]
    src_port, dest_port, udp_len, checksum = struct.unpack('!4H', udp_header)
    packet_val = {
        'src_port': src_port,
        'dest_port': dest_port,
        'udp_len': udp_len,
        'checksum': checksum,
        'data': data
    }
    src_port, dest_port, checksum,  = 0, 0, 0
    udp_header = struct.pack('!4H', src_port, dest_port, udp_len, checksum)
    # packet_key = ip_header + udp_header + data
    packet_key = udp_header + data

    return packet_key, packet_val




