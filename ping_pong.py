from scapy.all import *

ip = IP(src="192.168.60.6", dst="10.9.0.6")
udp = UDP(sport=9090, dport=9090)
data = "Let the PingPong game start! \n"
pkt = ip/udp/data
send(pkt, verbose=0, iface='eth0')