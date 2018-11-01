#!/usr/bin/python
from scapy.all import *
pkt = sr1(IP(dst='192.168.2.107',src='192.168.2.106')/ICMP(type='echo-request'))
