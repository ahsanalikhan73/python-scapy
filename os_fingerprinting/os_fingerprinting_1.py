#!/usr/bin/env python
from scapy.all import *
from scapy.layers.inet import IP, ICMP

# ttl = 128 	--> Windows
# ttl = 64		--> Linux 

packet = IP(dst='192.168.0.102')/ICMP()
response = sr1(packet, timeout=2)

if response == None:
	print('[!] No Response ...!')

elif response.haslayer(IP):
	if response.getlayer(IP).ttl <= 64:
		os = 'Linux'
	else:
		os = 'Windows'
	print('[#] TTL Value %d  ===> %s ' % (response.getlayer(IP).ttl, os) )