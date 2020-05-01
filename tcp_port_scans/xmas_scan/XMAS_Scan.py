#! /usr/bin/python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

dst_ip = "192.168.0.102"
src_port = RandShort()
dst_port = 139

xmas_scan = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags="FPU"),timeout=3)	#  FIN, PSH, URG

if (str(type(xmas_scan))=="<type 'NoneType'>"):
	print('\n[*] Open|Filtered\n')

elif(xmas_scan.haslayer(TCP)):
	if(xmas_scan.getlayer(TCP).flags == 0x14):
		print('\n[-] Port is Closed...!\n')

elif(xmas_scan.haslayer(ICMP)):
	if(int(xmas_scan.getlayer(ICMP).type)==3 and int(xmas_scan.getlayer(ICMP).code) in [1,2,3,9,10,13]):
		print('\n[*] Filtered\n')


'''
If the server responds with the ICMP packet with an ICMP unreachable error type 3
and ICMP code 1, 2, 3, 9, 10, or 13, then the port is filtered and it cannot be 
inferred from the response whether the port is open or closed.

'''