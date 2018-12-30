'''
    @author - mrdrivingduck
    @version - 2018.12.31
    @function - 
        The sniffer thread.
        Pushing the captured packets into buffer.
'''

import threading
import json
from main import conf
from main import buff
from logger import serverLogger
from scapy.all import *
from message.packetmessage import PacketMessage

def callback(packet):

    if ("TCP" or "UDP") in packet.summary():
        src_port = int(packet.sprintf("%sport%"))
        dst_port = int(packet.sprintf("%dport%"))
        src_ip = packet.sprintf("%IP.src%")
        dst_ip = packet.sprintf("%IP.dst%")
        src_mac = packet.sprintf("%src%")
        dst_mac = packet.sprintf("%dst%")
        msg = PacketMessage(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port)

        overflow = buff.push(json.dumps(msg, default=lambda obj: obj.__dict__))
        if overflow != None:
            serverLogger.warning("Packet overflowed from buffer")
        serverLogger.info("Captured packet")

def snifferThread():
    sniff(prn=callback)
    # sniff(prn=callback, iface=conf.getInet())