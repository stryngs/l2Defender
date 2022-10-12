#!/usr/bin/python3

from lib import L2_arp
from lib import menu
from scapy.all import *

class Shared(object):
    """One object to control them all"""
    __slots__ = ['arpAlerter']
    def __init__(self, args):
        self.arpAlerter = L2_arp.L2_arpListener(args)

if __name__ == '__main__':

    ## Menu creation
    MENU = menu.Menu()
    args = MENU.parser.parse_args()

    ## Create a shared object and run the initial demo for arp
    ### This will be moved to lib.main once threading is needed
    sh = Shared(args)
    sh.arpAlerter.sniffer()
