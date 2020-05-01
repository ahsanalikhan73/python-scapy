#!/usr/bin/env python 
import scapy.all as scapy

print('\nLive Sniffing ...\n')
packet = scapy.sniff(prn=lambda x:x.summary(), count=20)	# capture 20 packets of any type
print('\nTotal Packets Captured:' + str(len(packet)))


'''
-----------------------------------------------------------------------------------
Parameters:
	iface  			 --> specify interface
	filter=''  		 --> only collects ICMP protocol packets
	count = value    --> only collect specified number of packets
	store=True/False --> Doesn't consume memory
	timeout:         -->  Stop sniffing after a given time (default: None)
-----------------------------------------------------------------------------------

Sniff Only Specific Type of Packets e.g., 
icmp = scapy.sniff(iface='your-interface', filter='icmp', store=False)
print(icmp.summary())

-----------------------------------------------------------------------------------

pkt[0]        	--> display details of 1st packet
pkt[0].src	  	--> display src MAC
pkt[0].dst	   	--> display dst MAC
pkt[1]			--> display details of 2nd packet

pkt[0][1].src	--> display src IP
pkt[0][1].dst	--> display dst IP

hexdump(pkt)	--> hex value of a packet
hexdump(pkt[0])	--> hex value of 1st packet and so on...
raw(pkt[0])		--> raw data of 1st packet
Ether(pkt[0])	--> Ethernet data ( load value )

-----------------------------------------------------------------------------------

							Reading and writting Pcap files...!

Writting pcap Files:
---------------------

	rdpcap 		--> read pcap file
	wrpcap		--> write captured packets to a pcap file

packet = sniff(iface='interface-name', filter='tcp or port 80', count=2)

wrpcap('C:\\Users\\Ahsan Ali SN\\Desktop\\file.pcap', packet)  --> In Windows
wrpcap('C:\Users\Ahsan Ali SN\Desktop\file.pcap', packet)  	   --> In Linux  (no need to double the slash)

open this packet directly in wireshark as:
wireshark(packet) 		--> Linux


Reading pcap Files:
---------------------

pkt = rdpcap('C:\\Users\\Ahsan Ali SN\\Desktop\\file.pcap')
pkt.summary()
pkt.show()


Reading .pcaps with a custom function
--------------------------------------

We can also use scapy’s sniff() function to read packets from a .pcap file using 
the "offline" argument as show here:

packets = sniff(offline='IBGP_adjacency.cap')

This will allow us to use the prn() function to import the packets with custom functions
 packetCount = 0

>>> def customAction(packet):
...    return f"{packet[0][1].src} ==> {packet[0][1].dst}"
...
>>> sniff(offline='IBGP_adjacency.cap', prn=customAction)
'''
