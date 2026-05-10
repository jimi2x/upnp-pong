#!/usr/bin/env python3
import random
from scapy.all import *
from scapy.layers.l2 import arping as scapy_arping
from scapy.all import conf as scapy_conf
from mac_vendor_lookup import MacLookup
import sys
import time
from datetime import datetime

###################################################################################
#  upnp-pong.py ---> Instructions & How To:                                       #
#                                                                                 #
#   [+] Discover uPNP and SSDP hosts and services:                                #
#        sudo python3 upnp-pong.py                                                #
#                                                                                 #
###################################################################################


print ("\n")
print ("▄▄ ▄▄ █████▄ ███  ██ █████▄   █████▄  ▄▄▄  ▄▄  ▄▄  ▄▄▄▄ ") 
print ("██ ██ ██▄▄█▀ ██ ▀▄██ ██▄▄█▀   ██▄▄█▀ ██▀██ ███▄██ ██ ▄▄ ")
print ("▀███▀ ██     ██   ██ ██       ██     ▀███▀ ██ ▀██ ▀███▀ ")
print("       Presented by Lost Rabbit Labs :: ver 0.1a")
print ("\n")

payload = "\r\n".join([
        'M-SEARCH * HTTP/1.1',
        'HOST: 239.255.255.250:1900',
        'Accept: */*',
        'MAN: "ssdp:discover"',
        'ST: ssdp:all',
        'MX: 1',
        '',
        ''])

payload2 = "\r\n".join([
        'M-SEARCH * HTTP/1.1',
        'HOST: 239.255.255.250:1900',
        'Accept: */*',
        'MAN: "upnp:rootdevice"',
        'ST: ssdp:all',
        'MX: 1',
        '',
        ''])

### initialize all vars
total_pongs = 0
n = random.randint(9001, 64001)
r1 = 1

newfilter = "udp and port 1900"
a = AsyncSniffer(filter=newfilter)
all_locs = []

while True:
    r1s = str(r1)
    print("🏓 [ROUND " + r1s + "] Serving up M-SEARCH Discovery packets -> 🏓\n")
    a.start()
    send(IP(dst="239.255.255.250") / UDP(sport=n,dport=1900) / payload,verbose=False)
    n = n + 1
    send(IP(dst="239.255.255.250") / UDP(sport=n,dport=1900) / payload2,verbose=False)
    time.sleep(20)
    packets = a.stop()
    all_ips = []
    for p in packets:
    # add timestamp to output before release
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            ipaddr = p[IP].src
            dstaddr = p[IP].dst
            srcmac = p[Ether].src
            dstmac = p[Ether].dst
        except:
            pass
            ipaddr = p[IPv6].src
            dstaddr = p[IPv6].dst
            srcmac = p[Ether].src
            dstmac = p[Ether].dst
        try:
            srcvendor = MacLookup().lookup(srcmac)
        except:
            pass
            srcvendor = "? "
        dstvendor = "mDNS Broadcast"
        raw_output = p[Raw]
        raw_output_str = raw_output.load
        raw_output = raw_output_str.decode("utf-8").replace("\r\n"," ").split(" ")
        location = ""
        for r in raw_output:
            if "http" in r:
                location = r
        print (ipaddr + " (" + srcmac + " / " + srcvendor + ") " + "~~> " + dstaddr + " (" + dstmac + " / " + dstvendor + ")")
        print(p[UDP].load.decode('UTF-8'))
        msg = p[UDP].load.decode('UTF-8')
        msg1 = msg.replace("\r\n",";")
        output = ""
        output = ipaddr + ";" + srcmac + ";" + srcvendor + ";" + dstaddr + ";" + dstmac + ";" + dstvendor + ";" + location + ";" + msg1 + "\n"
        outputfile = "SSDP_LOG.csv"
        with open (outputfile, "a") as outputfile:
            outputfile.write(output)
        all_ips.append(ipaddr)
    n = n + 1
    if n == 65534:
        n = 1337
    r1 = r1 + 1
    total_packets = len(packets)
    total_packets_str = str(total_packets)
    total_pongs = total_pongs + total_packets
    total_pongs_str = str(total_pongs)
    print("⚪ Received " + total_packets_str + " uPNP/SSDP responses! (NEW TOTAL: " + total_pongs_str + ") ⚪")
    for i in all_ips:
        print (i)
    for p in packets:
        raw_output = p[Raw]
        raw_output_str = raw_output.load
        raw_output = raw_output_str.decode("utf-8").replace("\r\n"," ").split(" ")
        location = ""
        for r in raw_output:
            if "http" in r:
                try:
                    all_locs.append(r)
                except:
                    pass
    if len(all_locs) > 0:
        all_locs = set(all_locs)
        newurls = ", ".join(all_locs)
        print ("\n🏆 New URLs Discovered 🏆\n" + newurls)
    print ("\n---------------------------------------------------\n")
    all_locs = []
    newurls = ""
sys.exit()
