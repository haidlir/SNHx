from __future__ import print_function

from ryu.lib.packet.arp import arp
from ryu.lib.packet.ethernet import ethernet
from ryu.lib.packet.packet import Packet
from ryu.ofproto import ether

from config import Config
from collector import Collector
from dhcp import DHCPServer

class ARP_Handler(object):

    # Opcode 1 -> Request
    # Opcode 2 -> Reply

    @classmethod
    def receive_arp(cls, datapath, packet, etherFrame, inPort):
        arpPacket = packet.get_protocol(arp)

        if arpPacket.opcode == 1:
            arp_dstIp = arpPacket.dst_ip
            # LOG.debug("receive ARP request %s => %s (port%d)"
                       # %(etherFrame.src, etherFrame.dst, inPort))
            cls.reply_arp(datapath, etherFrame, arpPacket, arp_dstIp, inPort)
        elif arpPacket.opcode == 2:
            pass

    @classmethod
    def reply_arp(cls, datapath, etherFrame, arpPacket, arp_dstIp, inPort):
        dstIp = arpPacket.src_ip
        srcIp = arpPacket.dst_ip
        dstMac = etherFrame.src

        if arp_dstIp == DHCPServer.dhcp_server[datapath]:
            srcMac = Config.controller_macAddr
        elif arp_dstIp in Collector.arp_table:
            srcMac = Collector.arp_table[arp_dstIp].mac_addr
        else:
            return

        cls.send_arp(datapath, 2, srcMac, srcIp, dstMac, dstIp, inPort)
        # LOG.debug("send ARP reply %s => %s (port %d)" %(srcMac, dstMac, inPort))

    @classmethod
    def send_arp(cls, datapath, opcode, srcMac, srcIp, dstMac, dstIp, outPort):
        if opcode == 1:
            targetMac = "00:00:00:00:00:00"
            targetIp = dstIp
        elif opcode == 2:
            targetMac = dstMac
            targetIp = dstIp

        e = ethernet(dstMac, srcMac, ether.ETH_TYPE_ARP)
        a = arp(1, 0x0800, 6, 4, opcode, srcMac, srcIp, targetMac, targetIp)
        p = Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()

        actions = [datapath.ofproto_parser.OFPActionOutput(outPort, 0)]
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=0xffffffff,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=p.data)
        datapath.send_msg(out)