from scapy.all import *
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, ICMP

MAC_V_real = "02:42:c0:a8:3c:0b"
ether = Ether(dst=MAC_V_real)

ip = IP(src="192.168.60.6", dst="10.9.0.255")
icmp = ICMP(type=8)

frame = ether/ip/icmp
sendp(frame, iface='eth0')