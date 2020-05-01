#!/usr/bin/env python


from logging import getLogger, ERROR
getLogger('scapy.runtime').setLevel(ERROR)
from scapy.all import *
import sys
from datetime import datetime

if len(sys.argv) !=4:
    print('Usage : % target startport endport' % (sys.argv[0]))
    sys.exit(0)

target = str(sys.argv[1])
startport = int(sys.argv[2])
endport = int(sys.argv[3])

print('Scanning ' + target + ' For Open TCP Ports...\n')
start_time = datetime.now()

if startport == endport:
    endport+=1

for x in range(startport, endport):
    packet = IP(dst=target)/TCP(dport=x, flags='S')
    response = sr1(packet, timeout=0.5, verbose=False)
    if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
        print('Port ' + str(x) + ' is Open!')
    sr(IP(dst=target)/TCP(dport=response.sport, flags='R'), timeout=0.5, verbose=False)
    
stop_time = datetime.now()
total_time = stop_time - start_time
print('Scan is Complete!')
print('Total Duration : ' + str(total_time))

