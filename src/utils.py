from scapy.all import *


def full_duplex(p):
    sess = "Other"
    if 'Ether' in p:
        if 'IPv6' in p:
            if 'TCP' in p:
                sess = str(sorted(["TCP", p[IPv6].src, p[TCP].sport, p[IPv6].dst, p[TCP].dport], key=str))
            elif 'UDP' in p:
                sess = str(sorted(["UDP", p[IPv6].src, p[UDP].sport, p[IPv6].dst, p[UDP].dport], key=str))
        elif 'IP' in p:
            if 'TCP' in p:
                sess = str(sorted(["TCP", p[IP].src, p[TCP].sport, p[IP].dst, p[TCP].dport], key=str))
            elif 'UDP' in p:
                sess = str(sorted(["UDP", p[IP].src, p[UDP].sport, p[IP].dst, p[UDP].dport], key=str))
        else:
            sess = p.sprintf("Ethernet type=%04xr,Ether.type%")
    return sess
