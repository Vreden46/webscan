#! /usr/bin/env python3

import random
from ipaddress import IPv4Network
from typing import List

from scapy.all import ICMP, IP, sr1, TCP




# Definition der benötigten Funktionen


#Portrange in Liste umwandeln
def parse_port_range(port_range):
    start, end = map(int, port_range.split('-'))
    if start < 0 or end < start or end > 65535:
        raise ValueError("Ungültiger Port-Bereich")

    port_list = list(range(start, end + 1))
    return port_list
#Portscan mit handshake
def port_scan(host: str, ports: List[int]):
    # Send SYN with random Src Port for each Dst port
    for dst_port in ports:
        src_port = random.randint(1025, 65534)
        resp = sr1(
            IP(dst=host)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=1,
            verbose=0,
        )
        if resp is None:
            print(f"{host}:{dst_port} is filtered (silently dropped).")

        elif(resp.haslayer(TCP)):
            if(resp.getlayer(TCP).flags == 0x12):
                send_rst = sr1(
                    IP(dst=host)/TCP(sport=src_port,dport=dst_port,flags='R'),
                    timeout=1,
                    verbose=0,
                )
                print(f"{host}:{dst_port} is open.")

            elif (resp.getlayer(TCP).flags == 0x14):
                print(f"{host}:{dst_port} is closed without any servie.")

        elif(resp.haslayer(ICMP)):
            if(
                int(resp.getlayer(ICMP).type) == 3 and
                int(resp.getlayer(ICMP).code) in (1, 2, 3, 9, 10, 13)
            ):
                print(f"{host}:{dst_port} is filtered (silently dropped/probably firewall).")

# Send ICMP ping request, wait for answer

#call of Portscan
host = "192.168.0.1"
ports = "80-90"
# Define TCP port range
port_range = parse_port_range(ports)

resp = sr1(IP(dst=str(host))/ICMP(), timeout=2, verbose=0)

if resp is None:
    print(f"{host} is down or not responding.")
elif (
    int(resp.getlayer(ICMP).type)==3 and
    int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]
):
    print(f"{host} is blocking ICMP.")
else:
    port_scan(str(host), port_range)



