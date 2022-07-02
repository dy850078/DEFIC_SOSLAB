from _datetime import datetime, timedelta
import logging
import random
import socket
import struct
from typing import List, Any

import src.settings as settings
from src.Packet import Packet
from src.tcp import TcpConnect


count = 0


class OsDeceiver:
    white_list = []

    def __init__(self, host, os):
        self.host = host
        self.os = os
        self.conn = TcpConnect(host)
        self.knocking_history = {}
        self.white_list = {}
        # self.port_seq = [random.randint(0, 65535) for _ in range(3)]
        self.port_seq = [4441, 5551, 6661]

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
                    src_port = pkt.l4_field['src_port']
                    if src_port not in rsp:
                        rsp[src_port] = []
                    rsp[src_port].append(packet)

                    f = open('rsp_record.txt', 'w')
                    f.write(str(rsp))
                    f.close()
            continue

    def load_file(self, pkt_type: str):
        logging.basicConfig(level=logging.INFO)
        file = open('os_record/%s/%s_record.txt' % (self.os, pkt_type), 'r')
        packet_dict = eval(file.readline())
        clean_packet_dict = {k: v for (k, v) in packet_dict.items() if v is not None}

        return clean_packet_dict

    def os_deceive(self):
        logging.basicConfig(level=logging.INFO)
        dec_count = 0
        # load packet reference
        template_dict = {
            'arp': self.load_file('arp'),
            'tcp': self.load_file('tcp'),
            'udp': self.load_file('udp'),
            'icmp': self.load_file('icmp')
        }
        logging.info(f'{self.os} template is loaded')

        while True:
            raw_pkt, _ = self.conn.sock.recvfrom(65565)
            pkt = Packet(packet=raw_pkt)
            pkt.unpack()
            proc = pkt.get_proc()

            if proc == 'tcp':
                """Free port"""
                if pkt.l3_field['dest_IP'] == Packet.ip_str2byte(self.host) and \
                        pkt.l4_field['dest_port'] in settings.FREE_PORT:
                    continue

                """Port Knocking"""
                self.add_knocking_history(pkt)
                if self.verify_knocking(pkt):
                    src = ip_byte2str(pkt.l3_field['src_IP'])
                    dst = ip_byte2str(pkt.l3_field['dest_IP'])
                    self.white_list[pkt.l3_field['src_IP']] = datetime.now()
                    logging.info(f"add {src} into white list.")
                    logging.info(f"{self.white_list}")
                if pkt.l3_field['src_IP'] in self.white_list:
                    if self.white_list[pkt.l3_field['src_IP']] + settings.white_list_validation >= datetime.now():
                        logging.info(f"legal user <{src}:{pkt.l4_field['src_port']}> ====> "
                                     f"<{dst}:{pkt.l4_field['dest_port']}>")
                        continue
                    # update status when the authentication of this source IP is expired
                    else:
                        logging.info(f"<{src}> authentication is expired")
                        self.white_list.pop(pkt.l3_field['src_IP'])
                    continue

            """OS Deceive"""
            if (pkt.l3 == 'ip' and pkt.l3_field['dest_IP'] == socket.inet_aton(self.host)) or \
                    (pkt.l3 == 'arp' and pkt.l3_field['recv_ip'] == socket.inet_aton(self.host)):
                req = pkt
                # proc = req.l3 if req.l4 == '' else req.l4
                rsp = deceived_pkt_synthesis(proc, req, template_dict)
                if rsp is not None:
                    dec_count += 1
                    print(f'send: {proc}, deceptive packet counter: {dec_count}')
                    self.conn.sock.send(rsp)
            continue

    def add_knocking_history(self, packet: Packet):
        try:
            self.knocking_history[packet.l3_field['src_IP']].append(packet.l4_field['dest_port'])
        except KeyError:
            self.knocking_history[packet.l3_field['src_IP']] = [packet.l4_field['dest_port']]

    def verify_knocking(self, packet: Packet):
        idx = []
        if packet.l3_field['src_IP'] in self.white_list:
            self.knocking_history.pop(packet.l3_field['src_IP'])
            return False

        try:
            for port in self.port_seq:
                idx.append(self.knocking_history[packet.l3_field['src_IP']].index(port))
        except ValueError:
            return False

        if all(idx[i + 1] - idx[i] == 1 for i in range(len(idx) - 1)):
            return True
        else:
            return False


def deceived_pkt_synthesis(proc: str, req: Packet, template: dict):
    key, _ = gen_key(proc, req.packet)
    rsp = b''

    try:
        raw_template = template[proc][key]
    except KeyError:
        return

    template = Packet(raw_template)
    template.unpack()

    if proc == 'tcp':
        # eth
        template.l2_field['dMAC'] = req.l2_field['sMAC']
        template.l2_field['sMAC'] = req.l2_field['dMAC']
        # ip
        template.l3_field['src_IP'] = req.l3_field['dest_IP']
        template.l3_field['dest_IP'] = req.l3_field['src_IP']
        # tcp
        template.l4_field['src_port'] = req.l4_field['dest_port']
        if template.l4_field['src_port'] == 80:
            print('8080880880808')
        template.l4_field['dest_port'] = req.l4_field['src_port']
        template.l4_field['seq'] = req.l4_field['ack_num']

        if template.l4_field['flags'] == 0:
            template.l4_field['ack_num'] = req.l4_field['seq']
        elif template.l4_field['flags'] == 43:
            template.l4_field['ack_num'] = req.l4_field['seq'] + 2
        else:
            template.l4_field['ack_num'] = req.l4_field['seq'] + 1

        if 8 in template.l4_field['kind_seq']:
            req_ts_val = req.l4_field['option_field']['ts_val']  # record packet's ts_val
            template.l4_field['option_field']['ts_echo_reply'] = req_ts_val

        rsp = Packet(proc=proc, l2_field=template.l2_field, l3_field=template.l3_field, l4_field=template.l4_field)

    elif proc == 'icmp':
        # eth
        template.l2_field['dMAC'] = req.l2_field['sMAC']
        template.l2_field['sMAC'] = req.l2_field['dMAC']
        # ip
        template.l3_field['src_IP'] = req.l3_field['dest_IP']
        template.l3_field['dest_IP'] = req.l3_field['src_IP']
        # icmp
        template.l4_field['ID'] = req.l4_field['ID']
        template.l4_field['seq'] = req.l4_field['seq']

        rsp = Packet(proc=proc, l2_field=template.l2_field, l3_field=template.l3_field, l4_field=template.l4_field)

    elif proc == 'udp':
        # eth
        template.l2_field['dMAC'] = req.l2_field['sMAC']
        template.l2_field['sMAC'] = req.l2_field['dMAC']
        # ip
        template.l3_field['src_IP'] = req.l3_field['dest_IP']
        template.l3_field['dest_IP'] = req.l3_field['src_IP']
        # icmp
        template.l4_field['ID'] = 0
        template.l4_field['seq'] = 0

        rsp = Packet(proc='icmp', l2_field=template.l2_field, l3_field=template.l3_field, l4_field=template.l4_field)

    elif proc == 'arp':
        # eth
        template.l2_field['dMAC'] = req.l2_field['sMAC']
        template.l2_field['sMAC'] = settings.mac
        # arp
        template.l3_field['sender_mac'] = settings.mac
        template.l3_field['sender_ip'] = socket.inet_aton(settings.host)
        template.l3_field['recv_mac'] = req.l3_field['sender_mac']
        template.l3_field['recv_ip'] = req.l3_field['sender_ip']

        rsp = Packet(proc=proc, l2_field=template.l2_field, l3_field=template.l3_field)

    else:
        pass

    if rsp != b'':
        rsp.pack()
        return rsp.packet


def gen_key(proc, packet):
    if proc == 'tcp':
        return gen_tcp_key(packet)
    elif proc == 'udp':
        return gen_udp_key(packet)
    elif proc == 'icmp':
        return gen_icmp_key(packet)
    elif proc == 'arp':
        return gen_arp_key(packet)
    else:
        return


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
    IHL_VERSION, TYPE_OF_SERVICE, total_len, pktID, FRAGMENT_STATUS, ttl, PROTOCOL, check_sum_of_hdr, src_IP, dest_IP = \
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
    IHL_VERSION, TYPE_OF_SERVICE, total_len, pktID, FRAGMENT_STATUS, ttl, PROTOCOL, check_sum_of_hdr, src_IP, dest_IP = \
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
    IHL_VERSION, TYPE_OF_SERVICE, total_len, pktID, FRAGMENT_STATUS, ttl, PROTOCOL, check_sum_of_hdr, src_IP, dest_IP \
        = struct.unpack('!BBHHHBBH4s4s', ip_header)
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
    src_port, dest_port, checksum, = 0, 0, 0
    udp_header = struct.pack('!4H', src_port, dest_port, udp_len, checksum)
    # packet_key = ip_header + udp_header + data
    packet_key = udp_header + data

    return packet_key, packet_val


def ip_byte2str(ip_byte):
    ip = list(struct.unpack('!4B', ip_byte))
    for i in range(len(ip)):
        ip[i] = str(ip[i])
    return '.'.join(ip)
