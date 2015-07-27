# This file contains configuration of SNHx
from __future__ import print_function

class Config(object):

    controller_macAddr = '0a:e4:1c:d1:3e:44' # ganti yang cantik !!!

    # service option = {L2_Fabric, L3_Fabric, WAN}
    # L2_Fabric use single IP address subnet
    # L3_Fabric use many IP address subnets (a subnet per-switch/datapath)
    # WAN use static IP addressing
    # So be caution of the underlying network configuration
    service = 'L2_FABRIC'