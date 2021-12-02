import logging
import socket
import struct
import src.settings as settings
from src.tcp import TcpConnect, getIPChecksum, getTCPChecksum


class PortDeceiver:

    def __init__(self, host):
        self.host = host
        self.conn = TcpConnect(host)

    def send_packet(self, recv_flags, reply_flags):
        while True:
            packet, _ = self.conn.sock.recvfrom(65565)
            eth_header = packet[: settings.ETH_HEADER_LEN]
            eth = struct.unpack('!6s6sH', eth_header)
            eth_protocol = socket.ntohs(eth[2])

            if eth_protocol != 8:
                continue

            # build eth_header
            eth_dMAC = eth[0]
            eth_sMAC = eth[1]
            reply_eth_dMAC = eth_sMAC
            reply_eth_sMAC = eth_dMAC
            reply_eth_header = struct.pack('!6s6sH', reply_eth_dMAC, reply_eth_sMAC, eth[2])

            ip_header = packet[settings.ETH_HEADER_LEN: settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN]
            IHL_VERSION, TYPE_OF_SERVICE, total_len, pktID, FRAGMENT_STATUS, TIME_TO_LIVE, PROTOCOL, check_sum_of_hdr, \
                    src_IP, dest_IP = struct.unpack('!BBHHHBBH4s4s', ip_header)

            if dest_IP != socket.inet_aton(self.conn.dip):
                continue

            # tcp=0x06
            if PROTOCOL != 6:
                continue

            # build ip_header
            pktID = 456  # arbitrary number
            reply_src_IP = dest_IP
            reply_dest_IP = src_IP
            check_sum_of_hdr = 0
            reply_ttl = TIME_TO_LIVE + 1
            total_len = 40
            reply_ip_header = struct.pack('!BBHHHBBH4s4s', IHL_VERSION, TYPE_OF_SERVICE, total_len, pktID,
                                          FRAGMENT_STATUS, reply_ttl, PROTOCOL, check_sum_of_hdr,
                                          reply_src_IP, reply_dest_IP)
            check_sum_of_hdr = getIPChecksum(reply_ip_header)
            reply_ip_header = struct.pack('!BBHHHBBH4s4s', IHL_VERSION, TYPE_OF_SERVICE, total_len, pktID,
                                          FRAGMENT_STATUS, reply_ttl, PROTOCOL, check_sum_of_hdr,
                                          reply_src_IP, reply_dest_IP)

            tcp_header = packet[settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN: settings.ETH_HEADER_LEN
                                                        + settings.IP_HEADER_LEN + settings.TCP_HEADER_LEN]
            src_port, dest_port, seq, ack_num, offset, flags, window, checksum, urgent_ptr = struct.unpack('!HHLLBBHHH',
                                                                                                           tcp_header)

            if flags in recv_flags:
                print('receive flag=' + str(flags))
                pass
            else:
                continue

            reply_seq = ack_num
            reply_ack_vum = seq + 1
            reply_src_port = dest_port
            reply_dest_port = src_port
            num_recv = len(recv_flags)

            for i in range(num_recv):
                if flags == recv_flags[i]:
                    if reply_flags[i] == 0:
                        continue
                    reply_tcp_header = self.conn.build_tcp_header_from_reply(5, reply_seq, reply_ack_vum,
                                                                             reply_src_port, reply_dest_port,
                                                                             reply_src_IP, reply_dest_IP,
                                                                             reply_flags[i])
                    packet = reply_eth_header + reply_ip_header + reply_tcp_header
                    self.conn.sock.send(packet)
                    print('reply flag=' + str(reply_flags[i]))

            return True

    def sT(self, deceive_status):
        if deceive_status == 'open':
            self.send_packet([2], [18])
        elif deceive_status == 'close':
            self.send_packet([2, 1, 0, 41, 16], [20, 20, 20, 20, 20])
        else:
            logging.warning('Unknown deceive status')

    def deceive_ps_hs(self, port_status):
        if port_status == 'open':
            port_flag = 18
            print('deceive open')
        elif port_status == 'close':
            port_flag = 20
            print('deceive close')
        # count = 0

        while True:
            packet, _ = self.conn.sock.recvfrom(65565)
            eth_header = packet[: settings.ETH_HEADER_LEN]
            eth = struct.unpack('!6s6sH', eth_header)
            eth_protocol = socket.ntohs(eth[2])

            if eth_protocol != 8:
                continue

            # build eth_header
            eth_dMAC = eth[0]
            eth_sMAC = eth[1]
            reply_eth_dMAC = eth_sMAC
            reply_eth_sMAC = eth_dMAC
            reply_eth_header = struct.pack('!6s6sH', reply_eth_dMAC, reply_eth_sMAC, eth[2])

            ip_header = packet[settings.ETH_HEADER_LEN: settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN]
            IHL_VERSION, TYPE_OF_SERVICE, total_len, pktID, FRAGMENT_STATUS, TIME_TO_LIVE, PROTOCOL, check_sum_of_hdr, \
                src_IP, dest_IP = struct.unpack('!BBHHHBBH4s4s', ip_header)
            '''
            if dest_IP != socket.inet_aton(self.sip) or src_IP != socket.inet_aton(self.dip):
                continue
            '''

            if dest_IP != socket.inet_aton(self.conn.dip):
                continue

            # build ip_header
            pktID = 456  # arbitrary number
            reply_src_IP = dest_IP
            reply_dest_IP = src_IP
            check_sum_of_hdr = 0
            reply_ttl = TIME_TO_LIVE + 1
            total_len = 40
            reply_ip_header = struct.pack('!BBHHHBBH4s4s', IHL_VERSION, TYPE_OF_SERVICE, total_len, pktID,
                                          FRAGMENT_STATUS,
                                          reply_ttl, PROTOCOL, check_sum_of_hdr, reply_src_IP, reply_dest_IP)
            check_sum_of_hdr = getIPChecksum(reply_ip_header)
            reply_ip_header = struct.pack('!BBHHHBBH4s4s', IHL_VERSION, TYPE_OF_SERVICE, total_len, pktID,
                                          FRAGMENT_STATUS,
                                          reply_ttl, PROTOCOL, check_sum_of_hdr, reply_src_IP, reply_dest_IP)

            # tcp=0x06
            if PROTOCOL == 6:
                if port_status == 'record':
                    f = open('pkt_record.txt', 'a')
                    f.write(str(packet) + '\n')
                    continue
                tcp_header = packet[settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN: settings.ETH_HEADER_LEN +
                                    settings.IP_HEADER_LEN + settings.TCP_HEADER_LEN]
                src_port, dest_port, seq, ack_num, offset, flags, window, checksum, urgent_ptr = struct.unpack(
                    '!HHLLBBHHH', tcp_header)

                reply_seq = ack_num
                reply_ack_vum = seq + 1
                reply_src_port = dest_port
                reply_dest_port = src_port

                if flags == 2:
                    print('receive syn')
                    # reply ack_rst
                    reply_tcp_header = self.conn.build_tcp_header_from_reply(5, reply_seq, reply_ack_vum,
                                                                             reply_src_port, reply_dest_port,
                                                                             reply_src_IP, reply_dest_IP, port_flag)
                # receive ack receive
                elif flags == 16:
                    # reply rst
                    print('receive ack')
                    reply_tcp_header = self.conn.build_tcp_header_from_reply(5, reply_seq, reply_ack_vum,
                                                                             reply_src_port, reply_dest_port,
                                                                             reply_src_IP, reply_dest_IP, 4)
                elif port_status == 'close':  # flag != syn or ack and status == close
                    reply_tcp_header = self.conn.build_tcp_header_from_reply(5, reply_seq, reply_ack_vum,
                                                                             reply_src_port, reply_dest_port,
                                                                             reply_src_IP, reply_dest_IP, port_flag)
                else:
                    continue

                packet = reply_eth_header + reply_ip_header + reply_tcp_header
                self.conn.sock.send(packet)
                continue

            # icmp=0x01
            elif PROTOCOL == 1:
                if port_status == 'record':
                    continue
                icmp_header = packet[settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN: settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN + settings.ICMP_HEADER_LEN]
                data = packet[settings.ETH_HEADER_LEN + settings.IP_HEADER_LEN + settings.ICMP_HEADER_LEN:]
                icmp_type, code, checksum, pktID, seq = struct.unpack('BbHHh', icmp_header)
                pktID = 456

                if icmp_type == 8:
                    print('receive icmp8 & reply icmp0')
                    icmp_type = 0
                elif icmp_type == 13:
                    print('receive icmp13 & reply icmp14')
                    icmp_type = 14

                checksum = 0
                pseudo_packet = struct.pack('BbHHh', icmp_type, code, checksum, pktID, seq) + data
                checksum = getTCPChecksum(pseudo_packet)
                reply_icmp_header = struct.pack('BbHHh', icmp_type, code, checksum, pktID, seq)
                packet = reply_eth_header + reply_ip_header + reply_icmp_header + data
                self.conn.sock.send(packet)
                continue

            else:
                continue






