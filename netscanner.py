#!/bin/env python
import scapy.all as scapy
from scapy.layers.l2 import ARP, Ether
import argparse

def print_banner():
   print("  _ __  ___  ___ __ _ _ __  _ __   ___ _ __  ")
   print(" | '_ \/ __|/ __/ _` | '_ \| '_ \ / _ \ '__| ")
   print(" | | | \__ \ (_| (_| | | | | | | |  __/ |  ")
   print(" |_| |_|___/\___\__,_|_| |_|_| |_|\___|_|  \n               [+] created by Josva_rahul ")


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-r","--range",dest="range",help="enter the range of ip to scan example: -r 192.168.1.1/24")
    options = parser.parse_args()
    if not options.range:
        print("[-] please specify the range for the ip address")
        exit()
    return options

def scan(ip):
    arp_packet = ARP(pdst=ip, hwdst="ff:ff:ff:ff:ff:ff")
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_broadcast = broadcast/arp_packet
    answered_list = scapy.srp(arp_broadcast, timeout=1, verbose=False)[0]
    client_list = []
    for elements in answered_list:
        client_dict = {"IP":elements[1].psrc,"mac":elements[1].hwsrc }
        client_list.append(client_dict)
    return client_list


def print_results(results_list):
    print("--------------------------------------------------------")
    print("IP\t\t\tMAC ADDRESS\n---------------------------------------------------------")
    for clients in results_list:
        print(clients["IP"]+"\t\t"+clients["mac"])



options=get_arguments()
print_banner()
scan_results=scan(options.range)
print_results(scan_results)