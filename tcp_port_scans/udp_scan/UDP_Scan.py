#! /usr/bin/python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *


def udp_scan(dst_ip,dst_port,dst_timeout):
	udp_scan_resp = sr1(IP(dst=dst_ip)/UDP(dport=dst_port),timeout=dst_timeout)
	if (str(type(udp_scan_resp))=="<type 'NoneType'>"):
		retrans = []
		for count in range(0,3):
			retrans.append(sr1(IP(dst=dst_ip)/UDP(dport=dst_port),timeout=dst_timeout))
			for item in retrans:
				if (str(type(item))!="<type 'NoneType'>"):
					udp_scan(dst_ip,dst_port,dst_timeout)	# function call
					return '\n[*] Open|Filtered\n'

	elif (udp_scan_resp.haslayer(UDP)):
		return '\n[-] Port is Open...!\n'

	elif(udp_scan_resp.haslayer(ICMP)):
		if(int(udp_scan_resp.getlayer(ICMP).type)==3 and int(udp_scan_resp.getlayer(ICMP).code)==3):
			return '\n[-] Port is Closed...!\n'

	elif(int(udp_scan_resp.getlayer(ICMP).type)==3 and int(udp_scan_resp.getlayer(ICMP).code) in [1,2,9,10,13]):
		return '\n[*] Filtered\n'


if __name__ == '__main__':

	dst_ip = "192.168.0.102"
	src_port = RandShort()
	dst_port = 53
	dst_timeout = 3

	udp_scan(dst_ip, dst_port, dst_timeout)




'''
TCP is a connection-oriented protocol and UDP is a connection-less protocol.
A connection-oriented protocol is a protocol in which a communication channel should be 
available between the client and server and only then is a further packet transfer made.
If there is no communication channel between the client and the server, then no further 
communication takes place.
A Connection-less protocol is a protocol in which a packet transfer takes place without
checking if there is a communication channel available between the client and the server.
The data is just sent on to the destination, assuming that the destination is available.
'''