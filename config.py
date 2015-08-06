# This file contains configuration of SNHx
from __future__ import print_function

class Config(object):

    controller_macAddr = '0a:e4:1c:d1:3e:44' # ganti yang cantik !!!

    # service's options = {L2_FABRIC, L3_FABRIC}
    # L2_Fabric use single IP address subnet
    # L3_Fabric use many IP address subnets (a subnet per-switch/datapath/br(ovs))
    # The Addressing scheme handled by DHCP Server, static addressing won't work.
    service = 'L3_FABRIC'

    # route
    # 
    #
    route = {}

    # forwarding's options = {IP, MPLS}
    forwarding = 'IP'

