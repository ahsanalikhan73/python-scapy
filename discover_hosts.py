#!/usr/bin/env python
from scapy.all import *

ans, unans = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst='192.168.0.1/24'), timeout=1, verbose=0)
print('\n________________________________________________________________\n')
print('\tIP Address\t\t\tMAC Address')
print('________________________________________________________________\n')
for client in ans:
	print('\t' + client[1].psrc + '\t\t\t' + client[1].hwsrc)
print('\n')

# You can also Discover Clients as:
# (Raw Form of Discoverd Clients)

# hosts = arping('192.168.0.1/24')
# print(hosts)