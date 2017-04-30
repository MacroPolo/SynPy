#!/usr/bin/env python

"""
Perform a TCP 3-Way Handshake and connection teardown in user space using
customisable packet parameters.

Built with [scapy](https://github.com/phaethon/scapy)

As packets are sent from user space, the kernel will likely send RST packets
in response to the unsollicited SYN/ACK responses. Ensure that your firewall
drops locally generated RST packets. For example:

iptables -A OUTPUT -p tcp --tcp-flags RST RST -s <local-ip> -j DROP
"""

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import random
import sys
import argparse

def get_args():
    """Parse user input, display help if no arguments provided"""
    parser = argparse.ArgumentParser(description="Handcrafted TCP handshake" \
        "and teardown in userspace.")
    opt_args = parser._action_groups.pop()
    req_args = parser.add_argument_group('required arguments')
    opt_args = parser.add_argument_group('optional arguments')
    req_args.add_argument("-S", "--source-ip", help="Source IP address", 
                        action="store", required=True)
    req_args.add_argument("-D", "--destination-ip", help="Destination IP address",
                        action="store", required=True)
    opt_args.add_argument("-s", "--source-port", help="Source TCP port", 
                        type=int, action="store", default=-1)
    req_args.add_argument("-d", "--destination-port", help="Destination TCP port",
                        action="store", type=int, required=True)
    opt_args.add_argument("--isn", help="Initial Sequence Number", action="store",
                        type=int, default=-1)
    opt_args.add_argument("--rwin", help="Initial Window Size", action="store",
                        type=int, default=8192)
    opt_args.add_argument("--wscale", help="Window Scale Factor", action="store",
                        type=int, default=0)
    opt_args.add_argument("--mss", help="Maximum Segment Size", action="store",
                        type=int, default=1460)
    opt_args.add_argument("--sack", help="SACK Permitted", action="store",
                        type=int, default=0)
    opt_args.add_argument("--tsval", help="Timestamp Value (TSval)",
                        action="store", type=int, default=0)

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    return(parser.parse_args())


def init_packet(args):
    """Create dictionary containing packet paramters"""
    src_ip = args.source_ip
    dst_ip = args.destination_ip
    dst_port = args.destination_port
    rwin = args.rwin

    if args.isn == -1:
        seq = random.getrandbits(32)
    else:
        seq = args.isn

    if args.source_port == -1:
        src_port = random.randrange(32768,61000)
    else:
        src_port = args.source_port

    tcp_options, timestamps = [], []

    if args.wscale != 0:
        tcp_options.append(('WScale', args.wscale))

    if args.mss != 0:
        tcp_options.append(('MSS', args.mss))

    if args.sack != 0:
        tcp_options.append(('SAckOK', b''))

    if args.tsval != 0:
        tsval = args.tsval
        tsecr = 0
        tcp_options.append(('Timestamp', (tsval, tsecr)))
        timestamps = [('Timestamp', (tsval, tsecr))]
    else: 
        timestamps = []

    print(tcp_options)

    packet_params = {"src_ip":src_ip, "dst_ip":dst_ip, "src_port":src_port,
                 "dst_port":dst_port, "rwin":rwin, "seq":seq, "ack":0, 
                 "tcp_options":tcp_options, "timestamps":timestamps}

    return packet_params


def update_timestamp(packet_params, previous):
    """If TCP timestamps are being used, extract tsecr from reply packets
    and increase TSval by one, every time this function is called.
    """
    # TODO change this so that the TSval increase is clock-based as per RFC7323
    # timestamp clock should tick by 1 every 1ms to 1s - lets aim for every 100ms
    reply_opts = dict(previous['TCP'].options)
    if 'Timestamp' in reply_opts:    
        tsecr = reply_opts['Timestamp'][0]
        tsval = packet_params['timestamps'][0][1][0] + 1
        packet_params['timestamps'] = [('Timestamp', (tsval, tsecr))]
    return packet_params


def update_seq_ack(packet_params, previous):
    """Increase Sequence and Acknowledgement number"""
    seq = packet_params.get("seq") + 1
    ack = previous.seq +1
    packet_params['seq'] = seq
    packet_params['ack'] = ack
    return packet_params


def packet_constructor(packet_params, packet_flags):
    """Craft an IP or TCP packet for sending"""
    src_ip = packet_params.get("src_ip")
    dst_ip = packet_params.get("dst_ip")
    src_port = packet_params.get("src_port")
    dst_port = packet_params.get("dst_port")
    seq = packet_params.get("seq")
    ack = packet_params.get("ack")
    rwin = packet_params.get("rwin")
    tcp_options = packet_params.get("tcp_options")
    timestamps = packet_params.get("timestamps")

    if packet_flags == 'IP':
        packet = IP(src=src_ip, dst=dst_ip)
    elif packet_flags == 'S':
        packet = TCP(sport=src_port, dport=dst_port, flags='S', seq=seq, 
                     window=rwin, options=tcp_options)
    else:
        packet = TCP(sport=src_port, dport=dst_port, flags=packet_flags, 
                     seq=seq, ack=ack, window=rwin, options=timestamps)
    
    return packet


def handshake(packet_params):
    """Perform TCP 3-Way Handshake and connection teardown"""
    ip = packet_constructor(packet_params, 'IP')
    syn = packet_constructor(packet_params, 'S')
    # send SYN, retrieve SYN/ACK
    synack = sr1((ip/syn), timeout=3, retry=3, verbose=0)

    if synack is None:
        print("ERROR: No SYN/ACK received from target. Please check the "
              "destination IP and Port are correct.")
        rst = packet_constructor(packet_params, 'R')
        send(ip/rst)
        sys.exit(1)

    # Update seq, ack and tcp timestamp clock (if required)
    packet_params = update_seq_ack(packet_params, synack)
    packet_params = update_timestamp(packet_params, synack)

    # send ACK to complete the establishing handshake
    ack = packet_constructor(packet_params, 'A')
    send(ip/ack)

    packet_params = update_timestamp(packet_params, synack)

    fin = packet_constructor(packet_params, 'FA')

    # send FIN, store FIN/ACK response
    finack = sr1((ip/fin), timeout=3, retry=2, verbose=1)

    if finack is None:
        print("ERROR: No FIN/ACK received from target.")
        rst = packet_constructor(packet_params, 'R')
        send(ip/rst)
        sys.exit(1)

    packet_params = update_seq_ack(packet_params, finack)
    packet_params = update_timestamp(packet_params, synack)

    # send ACK to complete the termination handshake
    ack = packet_constructor(packet_params, "A")
    send(ip/ack)

if __name__ == "__main__":
    args = get_args()
    packet_params = init_packet(args)
    handshake(packet_params)
