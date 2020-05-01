#! /usr/bin/python3
from logging import getLogger, ERROR
getLogger('scapy.runtime').setLevel(ERROR)
from scapy.all import *
import sys
from datetime import datetime
from time import strftime

try:
    target = input('[+] Enter Target IP Address : ')
    min_port= input('[+] Enter Minimum Port Number : ')
    max_port = input('[+] Enter Maximum Port Number : ')
    try:
        if int(min_port) >=0 and int(max_port) >=0 and int(max_port) >= int(min_port):
            pass
        else:
            print('\n[!] Invalid Range of Ports')
            print('Exiting...')
            sys.exit(1)
            
    except Exception:
            print('\n[!] Invalid Range of Ports')
            print('Exiting...')
            sys.exit(1)

except KeyboardInterrupt:
    print('\n[*] User Requested Shutdown...')
    print('[*] Exiting...')
    sys.exit(1)

ports = range(int(min_port), int(max_port)+1)
start_clock = datetime.now()
SYNACK = 0x12
RSTACT = 0x14

#check that target is Up
def checkhost(ip):
    conf.verb = 0
    try:
        ping = sr1(IP(dst = ip)/ICMP())
        print('\n[+] Target is Up! Begining Scan...')
    except Exception:
        print('\n[!] Couldn\'t Resolve Target')
        print('[!] Exiting...')
        sys.exit(1)

#Scanning a Given Port
def scanport(port):
    srcport = RandShort()
    conf.verb = 0   #this prevents output from sending packets from being printed to the screen
    SYNACKpkt = sr1(IP(dst= target)/TCP(sport=srcport, dport=port, flags='S'))
    pktflags = SYNACKpkt.getlayer(TCP).flags
    if pktflags == SYNACK:
        return True
    else:
        return False
    RSTpkt = IP(dst=target)/TCP(sport=srcport, dport=port, flags='R')
    send(RSTpkt)


    
#Using Our Functions
checkhost(target)
print('[*] Scanning Started at ' + strftime('%H:%M:%S') + '!\n')

for port in ports:
    status = scanport(port) #function call
    if status == True:
        print('Port ' + str(port) + ': Open')

#Wrapping it Up
stop_clock = datetime.now()
total_time = stop_clock - start_clock
print('\n[*] Scanning Finished!')
print('[*] Total Scan Duration: ' + str(total_time))



















