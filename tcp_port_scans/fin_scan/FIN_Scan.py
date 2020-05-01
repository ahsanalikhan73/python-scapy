#! /usr/bin/python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

dst_ip = "192.168.0.102"
src_port = RandShort()
dst_port = 800

fin_scan = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags="F"),timeout=3)

if (str(type(fin_scan))=="<type 'NoneType'>"):
	print('\n[*] Open|Filtered\n')

elif(fin_scan.haslayer(TCP)):
	if(fin_scan.getlayer(TCP).flags == 0x14):
		print('\n[-] Port is Closed...!\n')

elif(fin_scan.haslayer(ICMP)):
	if(int(fin_scan.getlayer(ICMP).type)==3 and int(fin_scan.getlayer(ICMP).code) in [1,2,3,9,10,13]):
		print('\n[*] Filtered\n')