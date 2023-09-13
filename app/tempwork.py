import scan
from scapy.all import ICMP, IP, sr1, TCP

my_list = []
# call of Portscan
host = "10.1.52.94"
ports = "80-90"

my_list = scan.finalscan(host, ports)

print(my_list)