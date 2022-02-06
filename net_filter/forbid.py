import binascii
from itertools import count
import socket
import struct
import argparse
import sys
import logging
import os
import traceback
import socket

log_file=logging.getLogger("scapy.runtime")
log_file.setLevel(logging.DEBUG)
log_file.addHandler(logging.FileHandler(filename='./forbid.log',mode='a'))
from scapy.all import Ether, IP, IPv6, TCP, sendp, conf, sniff
from random import randint


# Given command line arguements, method determines if this packet should be responded to
def ignore_packet(packet, proto,forbid_map):
    src_ip = packet[proto].src
    dst_ip = packet[proto].dst
    src_port = packet[TCP].sport
    dst_port = packet[TCP].dport

    if src_ip in forbid_map :
        if dst_port == forbid_map[src_ip] or '*'==forbid_map[src_ip]:
            return False
    elif '*' in forbid_map:
        if dst_port == forbid_map['*'] or '*'==forbid_map['*']:

            return False
    return True 

def send(packet):
    sendp(packet,iface='enp0s25')

def build_packet(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, seq, proto):
    eth = Ether(src=src_mac, dst=dst_mac, type=0x800)
    if proto == IP:
        ip = IP(src=src_ip, dst=dst_ip)
    elif proto == IPv6:
        ip = IPv6(src=src_ip, dst=dst_ip)
    else:
        return str(eth) #if unknown L2 protocol, send back dud ether packet
    tcp = TCP(sport=src_port, dport=dst_port, seq=seq, flags="R") # R表示reset标识的tcp包，会重置链接
    return eth/ip/tcp

def callback(packet):
    flags = packet.sprintf("%TCP.flags%")
    proto = IP
    src_mac = packet[Ether].src
    dst_mac = packet[Ether].dst
    src_ip = packet[proto].src
    dst_ip = packet[proto].dst
    src_port = packet[TCP].sport
    dst_port = packet[TCP].dport
    seq = packet[TCP].seq
    ack = packet[TCP].ack
    if IPv6 in packet:
        proto = IPv6
    
    if not ignore_packet(packet, proto,glob_forbid_map):

        log_file.info('src_ip:%s,src_port:%s,dst_ip:%s,dst_port:%s,flags:%s',src_ip,src_port,dst_ip,dst_port,str(packet[TCP].flags))
        log_file.debug('<---forbid')
            # send(build_packet(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, seq, proto)) # 向自己的进程也发送终止
        send(build_packet(dst_mac, src_mac, dst_ip, src_ip, dst_port, src_port, ack, proto)) # 向对方进程发送终止

glob_forbid_map = {'192.168.31.252':22}

conf.sniff_promisc = True
sniff(filter='tcp', prn=callback, store=0, promisc=1,timeout=100) # count,timeout 

