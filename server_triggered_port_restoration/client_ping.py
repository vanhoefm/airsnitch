from scapy.all import IP, ICMP, send

target_ip = "146.190.116.164"
packet = IP(dst=target_ip) / ICMP(type=8, id=0, seq=0) / b"etherexists"
send(packet)
