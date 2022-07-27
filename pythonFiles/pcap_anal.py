import pyshark
from scapy.all import *


#import pyshark
cap = pyshark.FileCapture('./sample.pcap')
cap.load_packets()
packet_amount = len([packet for packet in cap])
print(packet_amount)


c = pyshark.FileCapture(input_file='sample.pcap')
j = 0
for i in c:
    if "HTTP" in str(i.layers):
        # print(i.layers)
        if "user" in str(i) or "USER" in str(i):
            # print(i)
            j += 1
        if "DATA-TEXT-LINES" in str(i.layers):
            # print(i)
            if "user" in i or "USER" in i:
                print(i)
print(j)


def print_domain_name_of_packet(pcap_file, domain_name, ip_src="192.168.0.2"):
    types = {0: 'ANY', 255: 'ALL', 1: 'A', 2: 'NS', 3: 'MD', 4: 'MD', 5: 'CNAME',
             6: 'SOA', 7:  'MB', 8: 'MG', 9: 'MR', 10: 'NULL', 11: 'WKS', 12: 'PTR',
             13: 'HINFO', 14: 'MINFO', 15: 'MX', 16: 'TXT', 17: 'RP', 18: 'AFSDB',
             28: 'AAAA', 33: 'SRV', 38: 'A6', 39: 'DNAME'}

    dns_packets = rdpcap(pcap_file)
    i = 0
    for packet in dns_packets:
        if packet.haslayer(DNS):

            # print(packet.show())
            dst = packet[IP].dst
            rec_type = packet[DNSQR].qtype
            domain = packet[DNSQR].qname
            if domain_name in domain:
                print(domain)
                print(dst, types[rec_type])
                print(packet.show)
                if packet[IP].src == ip_src:
                    i += 1
            # print(packet[DNSQR].qname)

            #print(dst, types[rec_type])
        else:
            pass
            # print(packet.show())


def get_amount_of_dns_packets(pcap_file):
    types = {0: 'ANY', 255: 'ALL', 1: 'A', 2: 'NS', 3: 'MD', 4: 'MD', 5: 'CNAME',
             6: 'SOA', 7:  'MB', 8: 'MG', 9: 'MR', 10: 'NULL', 11: 'WKS', 12: 'PTR',
             13: 'HINFO', 14: 'MINFO', 15: 'MX', 16: 'TXT', 17: 'RP', 18: 'AFSDB',
             28: 'AAAA', 33: 'SRV', 38: 'A6', 39: 'DNAME'}

    dns_packets = rdpcap('./sample.pcap')
    for packet in dns_packets:
        if packet.haslayer(DNS):
            print(packet.show())
            dst = packet[IP].dst
            rec_type = packet[DNSQR].qtype
            print(dst, types[rec_type])


def get_amount_of_packets(pcap_file):
    cap = pyshark.FileCapture(pcap_file)
    cap.load_packets()
    packet_amount = len([packet for packet in cap])
    return packet_amount
