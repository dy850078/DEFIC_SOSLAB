import logging
import argparse
import src.settings as settings
from src.port_deceiver import PortDeceiver



logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)-5s %(message)s', datefmt='%Y-%m-%d %I:%M:%S %p')


def main():
    parser = argparse.ArgumentParser(description='Deceiver Demo')
    parser.add_argument('--host', action="store", help='ip')
    parser.add_argument('--port', action="store", help='port')
    parser.add_argument('--nic', action="store", help='nic')
    parser.add_argument('--sT', action="store_true", help='sT port scanning technique deceiver')
    parser.add_argument('--hs', action="store_true", help='port and host scanning technique deceiver')
    parser.add_argument('--open', action="store_true", help='designate port status -> open')
    parser.add_argument('--close', action="store_true", help='designate port status -> close')
    args = parser.parse_args()

    if args.nic:
        settings.NIC = args.nic

    if args.sT:
        deceiver = PortDeceiver(args.host, args.port)
        if args.open:
            deceiver.st_open()
        elif args.close:
            deceiver.st_close()
        else:
            logging.INFO('no port status is received')

    if args.hs:
        deceiver = PortDeceiver(args.host, args.port)
        if args.open:
            deceiver.deceive_ps_hs('open')
        elif args.close:
            deceiver.deceive_ps_hs('close')

    # deceiver = PortDeceiver(args.host, args.port)
    # deceiver.deceive_ps_hs()
    # conn = TcpConnect((args.host, int(args.port)))
    # conn.send_packet([41], [4])
    # conn.send_packet([2],[18])
    # conn.HD_send_packet()
    # conn.close()


if __name__ == '__main__':
    main()
