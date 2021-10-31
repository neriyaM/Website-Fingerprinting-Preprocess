from scapy.all import *

def full_duplex(p):
    sess = "Other"
    if 'Ether' in p:
        if 'IPv6' in p:
            if 'TCP' in p:
                sess = str(sorted(["TCP", p[IPv6].src, p[TCP].sport, p[IPv6].dst, p[TCP].dport], key=str))
            elif 'UDP' in p:
                sess = str(sorted(["UDP", p[IPv6].src, p[UDP].sport, p[IPv6].dst, p[UDP].dport], key=str))
            elif 'ICMP' in p:
                sess = str(sorted(["ICMP", p[IPv6].src, p[IPv6].dst, p[ICMP].code, p[ICMP].type, p[ICMP].id], key=str))
            else:
                sess = str(sorted(["IP", p[IPv6].src, p[IPv6].dst, p[IPv6].proto], key=str))
        elif 'ARP' in p:
            sess = str(sorted(["ARP", p[ARP].psrc, p[ARP].pdst], key=str))
        else:
            sess = p.sprintf("Ethernet type=%04xr,Ether.type%")
    return sess