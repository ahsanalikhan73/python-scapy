#!/usr/bin/env python
from logging import getLogger, ERROR
getLogger('scapy.runtime').setLevel(ERROR)
from scapy.all import *

dst_ip = 'hackthissite.org'
src_port = RandShort()
dst_port = 80

tcp_handshake = sr1(IP(dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags='S'), timeout=1)

if str(type(tcp_handshake)) == "<type 'NoneType'>":
	print('\n[-] Port is Closed...!\n')

elif tcp_handshake.haslayer(TCP):
	if tcp_handshake.getlayer(TCP).flags == 0x12: 	#SA (18)
	    send_rst = sr(IP(dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags='AR'), timeout=1)[0]
	    print('\n[+] Port is Open...!\n')

elif tcp_handshake.getlayer(TCP).flags == 0x14: 	# RA (20)
	print('\n[-] Port is Closed...!\n')