# Suppress Scapy IPv6 warning
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Begin our Scapy script.
from scapy.all import *


def handshake(dst, port):
    ip = Ether()/IP(dst=dst)
    tcp = TCP(dport=port, flags='S')
    print('\nSYN\n__________\n')
    print(ip/tcp).summary()
    pkt = srp1(ip/tcp, timeout=timeout)

    print('\nSYN_ACK\n__________\n')
    print(pkt.summary())

    print('\nACK\n__________\n')
    tcp = TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport, flags="A", seq=pkt[TCP].ack, ack=pkt[TCP].seq+1)
    print(ip/tcp).summary()
    sock = srp1(ip/tcp, timeout=timeout)

    print('\nSOCK\n__________\n')
    print(sock.summary())


if __name__ == '__main__':

    server = 'google.com'
    port = 80
    timeout = 5

    print('\nSend packet...')
    handshake(server, port)
