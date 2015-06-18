from __future__ import print_function
import sys, signal

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
from dhcp import DHCPServer
from ui import Cli


def _halt():
    print('stopping...')
    sys.exit(0)

class Main(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Main, self).__init__(*args, **kwargs)
        signal.signal(signal.SIGINT, _halt)
        print("SNH is running...")
        self.cli_thread = hub.spawn(self._cli)
        self.routing_thread = hub.spawn_after(10 ,self._routing)

    # Event saat switch setup
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, event):
        switch = event.msg.datapath
        print("switch hidup dengan id ", switch.id)

        Collector.switch[switch.id] = switch.ports
        Collector.topo[switch.id] = {}

        msg = event.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(port=ofproto.OFPP_CONTROLLER,
                                          max_len=ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(type_=ofproto.OFPIT_APPLY_ACTIONS,
                                             actions=actions)]
        mod = parser.OFPFlowMod(datapath=datapath,
                                priority=0,
                                match=parser.OFPMatch(),
                                instructions=inst)
        datapath.send_msg(mod)

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
        Collector.topo[event.link.src.dpid][event.link.dst.dpid] = 1

    # Event ada paket masuk ke Controller
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, event):
        msg = event.msg
        datapath = msg.datapath
        pkt = packet.Packet(data=msg.data)

        disc_eth = pkt.get_protocol(ethernet.ethernet)

        if disc_eth.ethertype == ether.ETH_TYPE_ARP:
            return

        if disc_eth.ethertype == ether.ETH_TYPE_LLDP:
            return

        if disc_eth.ethertype == ether.ETH_TYPE_IP:
            disc_ipv4 = pkt.get_protocol(ipv4.ipv4)

            if disc_ipv4.proto == inet.IPPROTO_UDP:
                disc_udp = pkt.get_protocol(udp.udp)
                if disc_udp.src_port == 68 and disc_udp.dst_port == 67:
                    pkt_dhcp = dhcp.dhcp.parser(pkt[3])
                    if not pkt_dhcp:
                        return
                    else:
                        port = msg.match['in_port']
                        DHCPServer._handle_dhcp(datapath, port, pkt)

    def _cli(self):
        Cli.main()
        print("stopping.....")
        app_mgr = app_manager.AppManager.get_instance()
        app_mgr.close()

    def _routing(self):
        while True:
            Collector.path = DFS.findAllPairsPath(Collector.topo)
            hub.sleep(30)