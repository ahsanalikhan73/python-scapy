#! /usr/bin/python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

dst_ip = "192.168.0.102"
src_port = RandShort()
dst_port = 80

ack_flag_scan_resp = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags="A"),timeout=3)

if (str(type(ack_flag_scan_resp))=="<type 'NoneType'>"):
	print('\n[*] Stateful Firewall Present(Filtered)\n')

elif(ack_flag_scan_resp.haslayer(TCP)):
	if(ack_flag_scan_resp.getlayer(TCP).flags == 0x4):		# R (4)
		print('\n[*] No Firewall(Unfiltered)\n')

elif(ack_flag_scan_resp.haslayer(ICMP)):
	if(int(ack_flag_scan_resp.getlayer(ICMP).type)==3 and int(ack_flag_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
		print('\n[*] Stateful Firewall Present(Filtered)\n')


'''
The TCP ACK scan is not used to find the open or closed state of a port; rather,
it is used to find if a stateful firewall is present on the server or not. It only 
tells if the port is filtered or not. This scan type cannot find the open/closed state
of the port.
'''