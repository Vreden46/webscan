from ipaddress import IPv4Network
from typing import List
import time
from scapy.all import ICMP, IP, sr1, TCP
import socket

def resolve_ip(target, deflist, name = 0):
    if name == 0:
        try:
            return socket.gethostbyname(target)
        except socket.gaierror:
            deflist.append(f"Could not resolve DNS for {target}")
            return None
    else:
        try:
            return socket.gethostbyaddr(target)[0]
        except (socket.herror, socket.gaierror):
            return target
def traceroute(target, deflist, max_hops=30):

    target_ip = resolve_ip(target, deflist)

    deflist.append(f"Routenverfolgung zu {target} mit der IP {target_ip}:")

    for ttl in range(1, max_hops + 1):

        # Send ICMP Echo Request with increasing TTL

        packet = IP(dst=target, ttl=ttl) / ICMP()
        start_time = time.time()
        reply = sr1(packet, verbose=False, timeout=1)
        end_time = time.time()

        if reply is None:
            # No reply received, print an asterisk to indicate a timeout
            deflist.append(f"{ttl}: *")
        else:
            # Reply received, print the IP address of the responding host
            round_trip_time = (end_time - start_time) * 1000
            current_time = 5
            show_time = ">"
            while current_time < round_trip_time:
                show_time += "-"
                current_time += 5

            replay_name = resolve_ip(reply.src, deflist, 1)
            deflist.append(f"{ttl}: {reply.src} {replay_name} {show_time} ({round_trip_time:.2f} ms)")

        if reply and reply.src == target_ip:

            deflist.append(f"Ziel: {target} mit mit  {ttl} Hops erreicht:")

            break

#if __name__ == "__main__":
    #target_host = input("Geben Sie den Zielhost (IP-Adresse oder DNS-Name) ein: ")
    #traceroute(target_host)