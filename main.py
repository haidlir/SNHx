from __future__ import print_function
import sys, signal, os
import logging
import thread

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import dpid as dpid_lib
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import udp
from ryu.lib.packet import dhcp
from ryu.lib import hub
from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link
from ryu.ofproto import ether
from ryu.ofproto import inet

from collector import Collector
from routing import DFS
from forwarding import Forwarding
from misc import ARP_Handler
from dhcp import DHCPServer
from ui import Cli
from lib import PortDets, LinkDets, curr_to_capacity

# FORMAT = '%(asctime)s %(message)s'
# logging.basicConfig(format=FORMAT)
LOG = logging.getLogger('SNHx')
LOG.setLevel(logging.DEBUG)

class Main(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Main, self).__init__(*args, **kwargs)
        print("SNH is running...")
        self.cli_thread = hub.spawn(self._cli)
        self.routing_thread = hub.spawn_after(10 ,self._routing)

    # Event saat switch setup
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, event):
        dp = event.msg.datapath
        print("switch hidup dengan id ", dp.id)

        Collector.datapaths[dp.id] = dp
        Collector.port_info[dp.id] = {}
        Collector.topo[dp.id] = {}
        Collector.flow_entry[dp.id] = {}

        def send_port_desc_stats_request(datapath):
            ofp_parser = datapath.ofproto_parser

            req = ofp_parser.OFPPortDescStatsRequest(datapath, 0)
            datapath.send_msg(req)

        # Postponed for 1 second, wait till all ports goes up.
        hub.spawn_after(1 ,send_port_desc_stats_request, dp)


        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        actions = [parser.OFPActionOutput(port=ofproto.OFPP_CONTROLLER,
                                          max_len=ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(type_=ofproto.OFPIT_APPLY_ACTIONS,
                                             actions=actions)]
        mod = parser.OFPFlowMod(datapath=dp,
                                priority=0,
                                match=parser.OFPMatch(),
                                instructions=inst)
        dp.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handler(self, event):

        for i,v in enumerate(event.msg.body):
            if (v.port_no < 60000):
                Collector.port_info[event.msg.datapath.id][v.port_no] = PortDets(i, v.name, v.port_no,
                                                                                 v.state, curr_to_capacity(v.curr))

    # Event saat switch closed
    @set_ev_cls(event.EventSwitchLeave)
    def switch_leaved_handler(self, event):
        switch = event.switch.dp
        print("ada switch mati dengan id", switch.id)

    @set_ev_cls(event.EventPortModify)
    def port_modified_handler(self, event):
        port = event.port
        LIVE_MSG = {False: 'DOWN', True: 'LIVE'}
        print("ada port berubah state di dpid %s port no %s status %s" % (port.dpid,port.port_no,
                                                                          LIVE_MSG[port.is_live()]))
    # Event laporan link topo
    @set_ev_cls(event.EventLinkAdd)
    def get_topo(self, event):
        Collector.topo[event.link.src.dpid][event.link.dst.dpid] = LinkDets(event.link.src.dpid,
                                                                            event.link.src.port_no)

    # Event ada paket masuk ke Controller
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, event):
        msg = event.msg
        datapath = msg.datapath
        pkt = packet.Packet(data=msg.data)
        inPort = msg.match['in_port']

        etherFrame = pkt.get_protocol(ethernet.ethernet)

        if etherFrame.ethertype == ether.ETH_TYPE_ARP:
            ARP_Handler.receive_arp(datapath, pkt, etherFrame, inPort)
            return

        if etherFrame.ethertype == ether.ETH_TYPE_LLDP:
            return

        if etherFrame.ethertype == ether.ETH_TYPE_IP:
            pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)

            if pkt_ipv4.proto == inet.IPPROTO_UDP:
                disc_udp = pkt.get_protocol(udp.udp)
                if disc_udp.src_port == 68 and disc_udp.dst_port == 67:
                    pkt_dhcp = dhcp.dhcp.parser(pkt[3])
                    if not pkt_dhcp:
                        return
                    else:
                        DHCPServer._handle_dhcp(datapath, inPort, pkt)
                        return

            # Forward packet
            Forwarding.unicast_internal(datapath, inPort, pkt, msg.data, msg.buffer_id)

    def _cli(self):
        Cli.main()
        # app_mgr = Main.AppManager.get_instance()
        # app_close()
        self.routing_thread.kill()
        self.stop()
        print("stopping")
        os.kill()
        # sys.exit()
        self.cli_thread.kill()

    def _routing(self):
        while True:
            Collector.path = DFS.findAllPairsPath(Collector.topo)
            print('done')
            hub.sleep(5)