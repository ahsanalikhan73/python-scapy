#!/usr/bin/env python
import scapy.all as scapy

trace = scapy.traceroute('hackthissite.org')
print(trace)

'''
YOu can also specify the Max TTL Value as:
	> scapy.traceroute('hackthissite.org', maxttl=20)

Windows traceroute uses ICMP protocol but scapy's traceroute don't uses ICMP protocol , 
it uses TCP protocol (different from standard traceroute)

scapy's traceroute sends all the packets at one time and does not wait for individual
responses to come , thus maxttl is important

'''