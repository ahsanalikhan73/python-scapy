#! /usr/bin/python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

dst_ip = "192.168.0.102"
src_port = RandShort()
dst_port = 25

stealth_scan = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=3)

if(str(type(stealth_scan))=="<type 'NoneType'>"):
	print('\n[*] Filtered\n')

elif(stealth_scan.haslayer(TCP)):
	if(stealth_scan.getlayer(TCP).flags == 0x12):	#SA (18)
		send_rst = sr(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="R"),timeout=3)
		print('\n[+] Port is Open...!\n')

elif (stealth_scan.getlayer(TCP).flags == 0x14):	# RA (20)
	print('\n[-] Port is Closed...!\n')

elif(stealth_scan.haslayer(ICMP)):
	if(int(stealth_scan.getlayer(ICMP).type)==3 and int(stealth_scan.getlayer(ICMP).code) in [1,2,3,9,10,13]):
		print('\n[*] Filtered\n')