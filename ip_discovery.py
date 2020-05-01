#!/usr/bin/env python
from scapy.all import *

addr = '192.168.1'
for x in range(1, 255):
    ans = sr1(IP(dst=addr + str(x))/ICMP(), verbose=0)
    if ans:
        print('[+] Host is Up: ' + ans.src)
