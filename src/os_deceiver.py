import socket
import struct
import src.settings as settings

from src.tcp import TcpConnect, getIPChecksum, unpack_tcp_option, pack_tcp_option, os_build_tcp_header_from_reply


class OsDeceiver:

    def __init__(self, host):
        self.host = host
        self.conn = TcpConnect(host)

    def os_record(self):
        packet_dict = {}
        packet_num = 0
        print('[!] self.conn.dip: ', self.conn.dip)

        while True:
            packet, _ = self.conn.sock.recvfrom(65565)
            eth_header = packet[: settings.ETH_HEADER_LEN]
            eth = struct.unpack('!6s6sH', eth_header)
            eth_protocol = socket.ntohs(eth[2])

            if eth_protocol != 8:
                continue

            ip_header = packet[settings.ETH_HEADER_LEN: settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN]
            IHL_VERSION, TYPE_OF_SERVICE, total_len, pktID, FRAGMENT_STATUS, TIME_TO_LIVE, PROTOCOL, check_sum_of_hdr, \
                src_IP, dest_IP = struct.unpack('!BBHHHBBH4s4s', ip_header)

            # tcp=6
            if PROTOCOL == 6:
                if src_IP == socket.inet_aton(self.conn.dip):

                    tcp_header = packet[settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN: settings.ETH_HEADER_LEN
                                                                + settings.IP_HEADER_LEN + settings.TCP_HEADER_LEN]
                    src_port, dest_port, seq, ack_num, offset, flags, window, checksum, urgent_ptr = struct.unpack(
                        '!HHLLBBHHH', tcp_header)

                    packet_num += 1
                    if src_port not in packet_dict:
                        packet_dict[src_port] = []
                    packet_dict[src_port].append(packet)
                    f = open('pkt_record.txt', 'w')
                    f.write(str(packet_dict))
                    print('[!] written to txt - total ', packet_num, 'packet(s)')

            continue

    def os_deceive(self):
        os_file = open('pkt_record.txt', 'r')
        packet_dict = eval(os_file.readline())
        print('[!] loading pcap file for packet reply...')

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
                tcp_header = packet[settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN: settings.ETH_HEADER_LEN +
                                    settings.IP_HEADER_LEN + settings.TCP_HEADER_LEN]
                src_port, dest_port, seq, ack_num, _, flags, _, _, _ = struct.unpack('!HHLLBBHHH', tcp_header)

                # received 'RST', don't reply
                if flags == 4:
                    continue

                if dest_port in packet_dict and len(packet_dict[dest_port]) != 0:
                    reply_packet = packet_dict[dest_port].pop(0)
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
                        print('[******] len(reply_tcp_option): ', len(reply_tcp_option))
                        total_len = len(reply_ip_header) + len(reply_tcp_header) + len(reply_tcp_option)
                        option_val, kind_seq = unpack_tcp_option(reply_tcp_option)
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

                    reply_src_port = dest_port
                    reply_dest_port = src_port
                    reply_seq = ack_num
                    reply_ack_num = seq + 1
                    tcp_len = (len(reply_tcp_header) + len(reply_tcp_option)) // 4
                    print('tcplen: ', tcp_len)
                    reply_tcp_header_option = os_build_tcp_header_from_reply(tcp_len, reply_seq, reply_ack_num,
                                                                             reply_src_port, reply_dest_port,
                                                                             reply_src_IP, reply_dest_IP, reply_flags,
                                                                             reply_window, reply_tcp_option)

                    packet = reply_eth_header + reply_ip_header + reply_tcp_header_option
                    print('[******] tcp/ip length', total_len)
                    print('[******] reply_tcp_option', reply_tcp_option)
                    print('[******]  reply_src_port', reply_src_port)
                    self.conn.sock.send(packet)
                    continue

                else:
                    continue
            else:
                continue






    '''
    def os_record(self):
        packet_dict = {}
        packet_num = 0
        print('[!] self.conn.dip: ', self.conn.dip)
        while True:
            packet, _ = self.conn.sock.recvfrom(65565)
            eth_header = packet[: settings.ETH_HEADER_LEN]
            eth = struct.unpack('!6s6sH', eth_header)
            eth_protocol = socket.ntohs(eth[2])

            if eth_protocol != 8:
                continue

            ip_header = packet[settings.ETH_HEADER_LEN: settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN]
            IHL_VERSION, TYPE_OF_SERVICE, total_len, pktID, FRAGMENT_STATUS, TIME_TO_LIVE, PROTOCOL, check_sum_of_hdr, \
                src_IP, dest_IP = struct.unpack('!BBHHHBBH4s4s', ip_header)

            # tcp=6
            if PROTOCOL == 6:
                if src_IP == socket.inet_aton(self.conn.dip):

                    tcp_header = packet[settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN: settings.ETH_HEADER_LEN +
                                        settings.IP_HEADER_LEN + settings.TCP_HEADER_LEN]
                    src_port, dest_port, seq, ack_num, offset, flags, window, checksum, urgent_ptr = struct.unpack(
                        '!HHLLBBHHH', tcp_header)

                    print('[!] src_IP: ', socket.inet_ntoa(src_IP), '      pkt_num: ', packet_num)
                    packet_num += 1
                    if src_port not in packet_dict:
                        packet_dict[src_port] = {}

                    if flags not in packet_dict[src_port]:
                        packet_dict[src_port][flags] = []

                    packet_dict[src_port][flags].append(packet)
                    f = open('os_record.txt', 'w')
                    f.write(str(packet_dict))
                    print('[!] written to txt')

            continue


    '''