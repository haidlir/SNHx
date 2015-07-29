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

    # if you pick WAN as the service
    # you have to configure where a network attached to a port and dpid into
    # example : 192.168.252.0/24 attached to dpid = 2456 port = 4
    #           192.168.31.0/27 attached to dpid = 31 port = 1
    #           set route = {'192.168.252.1/24': {2456: 4},
    #                        '192.168.31.1/27': {31: 1}
    #                       }
    route = {}

