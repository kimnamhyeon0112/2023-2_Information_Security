from scapy.all import *


x_ip = "10.9.0.5"
x_port = 9090
srv_ip = "10.9.0.69"
srv_port = 8000
syn_seq = 0x1000

ip = IP(src=srv_ip, dst=x_ip)
tcp = TCP(sport=srv_port, dport=x_port, seq=syn_seq, flags='S')

send(ip/tcp, verbose=1, iface='eth0')