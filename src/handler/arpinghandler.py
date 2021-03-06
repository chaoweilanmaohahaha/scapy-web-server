'''
    @author - mrdrivingduck
    @version - 2018.12.31
    @funtion - 
        Use Scapy to preform an ARPING function.
        The network segment is from HTTP GET URL.
    @configuration - 
        The time-out interval can be configured.
            section:[scapy]
            key:[arping_timeout]
'''

import tornado.web
import json
from logger import serverLogger
from globall import conf
from scapy.sendrecv import srp
from scapy.layers.l2 import Ether
from scapy.layers.l2 import ARP

class ArpingHandler(tornado.web.RequestHandler):

    def get(self, net):
        timeout = conf.getArpingTimeout()
        ans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=net),timeout=timeout, filter="arp and arp[7] = 2", iface_hint=net)
        ans = ans[0]

        arr = []
        for sendrecv in ans.res:
            recv = sendrecv[1]
            mac = recv.sprintf("%Ether.src%")
            ip = recv.sprintf("%ARP.psrc%")
            pair = dict(mac=mac, ip=ip)
            arr.append(pair)

        self.write(json.dumps(arr))

    def post(self):
        pass

    def prepare(self):
        serverLogger.info("Handler - ARPING request")

    def on_finish(self):
        serverLogger.info("Handler - ARPING complete")
    