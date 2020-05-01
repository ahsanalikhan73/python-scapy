#!/usr/bin/env python
from scapy.all import *

packet = IP(dst="1.1.1.1")/ICMP()
res = sr1(packet, verbose=False)

if res:
    print "\n---------------------------------------"
    print "Host is Up, trying DNS Query"
    print "---------------------------------------\n\n"
    packet = sr1(IP(dst="1.1.1.1") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="www.google.com")), verbose=False)
    print(packet.summary())
else:
    print "Destination Unreachable!"

'''
Note: 8.8.8.8 is the Google's DNS Server
rd  		--> Recursion Desired	--> repetition
qd 			--> Query Domain
DNSQR 		--> DNS query Record
qname   	--> query name
UDP()		--> Because DNS uses UDP to resolve IP's
RandShort()	--> Choosing Random Source Port

ans = sr(IP(dst='8.8.8.8')/UDP(sport=RandShort(), dport=53)/DNS(rd=1, qd=DNSQR(qname='www.bing.com')), verbose=0)[0]
'''