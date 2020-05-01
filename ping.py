#!/usr/bin/env python
from scapy.all import *

# Layer 3 Ping Scan
ping = IP(dst='hackthissite.org')/ICMP()
print(srloop(ping, count=5))


print('\nICMP Reply Packet:')
ping = sr(IP(dst='hackthissite.org')/ICMP(), verbose=False)[0]
print(ping.summary())

#it will displays the ICMP reply if the destination host is up.
'''
Two Scapy functions related to sending and receiving packets are the srloop() and srploop().

srloop() will send packets from layer 3 and continue to resend the packet after each response is received.
srploop() does the same thing except for… it sends the packets from layer 2 (you can modify you MAC Address)
count()	defines the number of times you want to loop.
'''