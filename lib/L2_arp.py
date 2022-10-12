"""
The point of this module will be to detect potentially malicious ARP traffic
"""

# import sqlite3 as lite
from scapy.all import *

class L2_arpListener(object):
    """Listens for ARP traffic and attempts to discern malicious traffic"""
    __slots__ = ['args', 'tracker']
    def __init__(self, args):
        print("Arp module loaded")
        self.args = args                                                        ### This needs to be handled at a higher level once more modules are created
        self.tracker = {}
        # self.con = lite.connect('l2d.sqlite3', isolation_level = None)        ### This needs to be handled at a higher level once more modules are created
        # self.db = self.con.cursor()
        # self.db.execute("""
        #                 CREATE TABLE IF NOT EXISTS arp(mac TEXT, ip TEXT)
        #                 ;""")

    def sniffer(self):
        pHandler = self.pHandler()
        self.p = sniff(iface = self.args.i, prn = pHandler, filter = 'arp')


    def pHandler(self):
        """
        prn in sniff()

        Runs if lfilter non-existent || lfilter returns True.

         ptype     = IPv4
         plen      = 4
         op        = is-at
        """
        def snarf(packet):
            if packet[ARP].ptype == 2048:
                if packet[ARP].plen == 4:
                    if packet[ARP].op == 2:

                        newMac = packet[Ether].src
                        newIp = packet[Ether].psrc

                        ## Never before seen MAC
                        if self.tracker.get(newMac) is None:
                            self.tracker.update({newMac: {newIp}})
                            print('New ~~~> {0} - {1}'.format(newMac, newIp))

                        ## We have seen this MAC before, now it is another IP
                        else:

                            ## Grab prior observations
                            ipSet = self.tracker.get(newMac)

                            ## Compare prior to new
                            if newIp in ipSet:
                                pass
                            else:
                                self.tracker.update({newMac: ipSet.union({newIp})})
                                print('POTENTIAL SPOOF ~~~> {0} - {1}'.format(newMac, newIp))
        return snarf
