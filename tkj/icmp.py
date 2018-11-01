from scapy.all import *
for i in range(6,10):
	print i
	ip = "192.168.2." + str(i)
	pkt = IP(dst=ip,src="192.168.2.104")/ICMP(type="echo-request")
	rep = sr1(pkt,timeout=4,verbose=0)
	if rep:
		print "The	" + rep[IP].src + "is life"

