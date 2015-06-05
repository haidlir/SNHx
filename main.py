from __future__ import print_function

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import dpid as dpid_lib
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib import hub
from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link

from collector import Collector
from routing import DFS
from ui import Cli


class Main(app_manager.RyuApp):

    def __init__(self, *args, **kwargs):
        super(Main, self).__init__(*args, **kwargs)
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

    def _cli(self):
        Cli.main()

    def _routing(self):
        while True:
            Collector.path = DFS.findAllPairsPath(Collector.topo)
            hub.sleep(30)