# NOTE: Global Constants
import datetime

ETH_HEADER_LEN = 14
IP_HEADER_LEN = 20
ARP_HEADER_LEN = 28
TCP_HEADER_LEN = 20
UDP_HEADER_LEN = 8
ICMP_HEADER_LEN = 8
L3_PROC = ['ip', 'arp']
L4_PROC = ['tcp', 'udp', 'icmp']
host = '10.1.100.233'


# NOTE: Settings
NIC = 'enp3s0'
NICAddr = '/sys/class/net/%s/address' % NIC
record_path = 'pkt_record.txt'
mac = b'\x00\x50\x56\xb0\x10\xe9'

# NOTE: Port Knocking
FREE_PORT = []
WHITE_LIST = []
PORT_SEQ = [2521, 4321, 1314]
white_list_validation = datetime.timedelta(seconds=30)
