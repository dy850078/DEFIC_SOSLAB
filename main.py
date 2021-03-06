import logging
import argparse
import src.settings as settings
from src.port_deceiver import PortDeceiver
from src.os_deceiver import OsDeceiver


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
    parser.add_argument('--os', action="store", help='designate os we want to deceive')
    args = parser.parse_args()
    settings.host = args.host

    if args.nic:
        settings.NIC = args.nic

    if args.scan:
        port_scan_tech = args.scan

        if port_scan_tech == 'ts':
            deceiver = OsDeceiver(args.host, args.os)
            deceiver.os_record()
        elif port_scan_tech == 'od':
            if args.os is None:
                logging.debug('No os is designated')
            else:
                deceiver = OsDeceiver(args.host, args.os)
                deceiver.os_deceive()
        elif port_scan_tech == 'rr':
            deceiver = OsDeceiver(args.host, args.os)
            deceiver.store_rsp()

        if args.status:
            deceive_status = args.status
            if port_scan_tech == 'pd':
                deceiver = PortDeceiver(args.host)
                deceiver.deceive_ps_hs(deceive_status)

        else:
            logging.debug('No port scan technique is designated')
            return

    else:
        logging.debug('No scan technique is designated')
        return


if __name__ == '__main__':
    main()
