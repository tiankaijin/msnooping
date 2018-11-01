#!/usr/bin/python
from scapy.all import *


def print_pkt(pkt):
	pkt.show()

pkt = sniff(filter='icmp',prn=print_pkt,count=1)
#pkt = sniff(filter='dst net 192.168.2 or src net 192.168.2',prn=print_pkt)
#pkt = sniff(filter='ip src 192.168.2.104 and tcp and tcp port 80',prn=print_pkt)
#pkt = sniff(filter='dst net 192.168.2 or src net 192.168.2',prn=print_pkt)
'''
a = IP()
a.dst = '192.168.2.103'
a.ttl = 1
b = ICMP()
send(a/b)
'''

'''
>>> pkt=IP(src='192.168.2.3',dst='192.168.2.107')/ICMP(type='echo-request')
>>> send(pkt,inter=1,count=1)
'''
