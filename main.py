import logging
import argparse
import src.settings as settings
from src.port_deceiver import PortDeceiver


logging.basicConfig(
            format='%(asctime)s [%(levelname)s]: %(message)s',
            datefmt='%y-%m-%d %H:%M',
            level=logging.INFO
        )


def main():
    parser = argparse.ArgumentParser(description='Deceiver Demo')
    parser.add_argument('--host', action="store", help='specify destination ip')
    parser.add_argument('--port', action="store", help='specify destination port')
    parser.add_argument('--nic', action="store", help='nic where we capture the packets')
    parser.add_argument('--scan', action="store", help='attacker\'s port scanning technique') 
    parser.add_argument('--status', action="store", help='designate port status') 
    args = parser.parse_args()

    if args.nic:
        settings.NIC = args.nic

    if args.scan:
        port_scan_tech = args.scan
        if args.status:
            deceive_status = args.status
            deceiver = PortDeceiver(args.host)
            if port_scan_tech == 's':
                deceiver.sT(deceive_status)
            elif port_scan_tech == 'hs':
                deceiver.deceive_ps_hs(deceive_status)
        else:
            logging.debug('No port scan technique is designated')
            return

    else:
        logging.debug('No port scan technique is designated')

if __name__ == '__main__':
    main()
