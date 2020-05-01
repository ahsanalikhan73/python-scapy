#! /usr/bin/python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

dst_ip = "192.168.0.102"
src_port = RandShort()
dst_port = 80

window_scan = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags="A"),timeout=3)

if (str(type(window_scan)) == "<type 'NoneType'>"):
	print('\n[*] No Response\n')

elif(window_scan.haslayer(TCP)):
	if(window_scan.getlayer(TCP).window == 0):
		print('\n[-] Port is Closed...!\n')

elif(window_scan.getlayer(TCP).window > 0):
	print('\n[+] Port is Open...!\n')