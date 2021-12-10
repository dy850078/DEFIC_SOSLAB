# NOTE: Global Constants
ETH_HEADER_LEN = 14
IP_HEADER_LEN = 20
TCP_HEADER_LEN = 20
ICMP_HEADER_LEN = 8

# NOTE: Settings
NIC = 'ens5'
NICAddr = '/sys/class/net/%s/address' % NIC
record_path = 'pkt_record.txt'

# NOTE: OS
cent_os = ''
