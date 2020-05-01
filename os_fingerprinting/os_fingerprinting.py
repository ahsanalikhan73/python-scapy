#!/usr/bin/env python
from scapy.all import *

ans = input('\nEnter Target IP: ')

reply = sr1(IP(dst=ans)/ICMP())
if reply.ttl < 65:
    os = 'Linux'
else:
    os = 'Windows'

print('\n[+] Operating System is ' + os)
    
