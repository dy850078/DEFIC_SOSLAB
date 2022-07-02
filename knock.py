from scapy.all import *
import sys

def main():
    """
    """
    packet = IP(dst="10.1.100.220")/TCP(dport=11)/"from scapy packet"
    send(packet)

def packet_with_seq_n():
    src_IP = sys.argv[1]
    dest_IP = sys.argv[2]
    d1 = int(sys.argv[3])
    d2 = int(sys.argv[4])
    d3 = int(sys.argv[5])

    packet11 = IP(dst=dest_IP, src=src_IP)/TCP(sport=333, dport=d1, seq=112345)/"Sequence number 112344"
    packet22 = IP(dst=dest_IP, src=src_IP)/TCP(sport=333, dport=d2, seq=112345)/"Sequence number 112344"
    packet33 = IP(dst=dest_IP, src=src_IP)/TCP(sport=333, dport=d3, seq=112345)/"Sequence number 112344"
    packet = [packet11, packet22, packet33]
    send(packet)
    # we can use sendp to choose different network interface
    # sendp(packet, iface="eth0")
    # lsc() can see functions descriptions.

if __name__ == "__main__":
    # main()
    packet_with_seq_n()


