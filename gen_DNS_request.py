from scapy.all import *

targetName = 'aaaaa.example.com'
dstIP = '10.9.0.53'
ip = IP(dst=dstIP)
udp = UDP(dport=53, chksum=0)
Qdsec = DNSQR(qname=targetName)
dns = DNS(id=100, qr=0, qdcount=1, qd=Qdsec)
Requestpkt = ip/udp/dns

with open('ip_req.bin', 'wb') as f:
    f.write(bytes(Requestpkt))