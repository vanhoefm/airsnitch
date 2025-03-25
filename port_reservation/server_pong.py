from scapy.all import sniff, IP, ICMP, send, Raw
import random

def handle_packet(packet):
    if packet.haslayer(ICMP) and packet[ICMP].type == 8:  # ICMP Echo Request
        if packet.haslayer(Raw) and b"etherexists" in packet[Raw].load:
            print(f"Received target ping from {packet[IP].src}")
            for i in range(5):  # Send 5 burst responses
                reply = IP(dst=packet[IP].src, src=packet[IP].dst, ttl=64) / \
                        ICMP(type=0, id=0, seq=0) / Raw(load="etherexists")
                send(reply, verbose=False)
                print("Sent out ICMP Reply", i)
            print("Sent burst of ICMP replies")

if __name__ == "__main__":
    print("Listening for ICMP echo requests with 'etherexists'...")
    sniff(filter="icmp", prn=handle_packet, store=0)