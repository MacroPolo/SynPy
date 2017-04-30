# SynPy

SynPy is a utility to handcraft a TCP handshake and teardown in userspace using the [Scapy for Python3](https://github.com/phaethon/scapy) library.

# Prerequisites

You will need to have Scapy for Python3 installed as per the intructions [here](https://github.com/phaethon/scapy#installation). In most cases, this can be quickly installed through `pip`:

```
pip3 install scapy-python3
```

# Usage

As a minimum, you must specify the source IP address that you want to send the packets from and the target IP address and port number. For example:

```
python synpy.py -S 192.168.1.67 -D 192.168.1.90 -d 80
```

In addition, there are also several optional parameters which will allow you to control further aspects of the TCP connection including source port, the initial sequence number used, the initial window size and various TCP options values:

```
# python synpy.py --help
usage: synpy.py [-h] -S SOURCE_IP -D DESTINATION_IP [-s SOURCE_PORT] -d
                DESTINATION_PORT [--isn ISN] [--rwin RWIN] [--wscale WSCALE]
                [--mss MSS] [--sack SACK] [--tsval TSVAL]

Handcrafted TCP handshakeand teardown in userspace.

required arguments:
  -S SOURCE_IP, --source-ip SOURCE_IP
                        Source IP address
  -D DESTINATION_IP, --destination-ip DESTINATION_IP
                        Destination IP address
  -d DESTINATION_PORT, --destination-port DESTINATION_PORT
                        Destination TCP port

optional arguments:
  -s SOURCE_PORT, --source-port SOURCE_PORT
                        Source TCP port
  --isn ISN             Initial Sequence Number
  --rwin RWIN           Initial Window Size
  --wscale WSCALE       Window Scale Factor
  --mss MSS             Maximum Segment Size
  --sack SACK           SACK Permitted
  --tsval TSVAL         Timestamp Value (TSval)
```

__Note__: Any non-zero integer will enable Selective Acknowledgement (SACK).

## My firewall is resetting the connection

As Scapy sends packets in userspace, iptables is not responsible for tracking state information regarding the TCP connections. As a result, when SYN/ACK packets are received, iptables will drop them as unsollicited packets and send a RST to the destination.

To workaround this, you will need to create an iptables rule which drops outbound RST packets. For example:

```
iptables -A OUTPUT -p tcp --tcp-flags RST RST -s <local-ip> -j DROP
```