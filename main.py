from __future__ import print_function
import sys
import signal
import os
import logging
import thread
import json

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
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from webob import Response

from config import Config
from collector import Collector
from routing import DFS, AllPairsSP
from forwarding import Forwarding, MPLSSetup
from misc import ARP_Handler
from dhcp import DHCPServer
from ui import Cli, RestAPI
from lib import PortDets, LinkDets, curr_to_capacity

# FORMAT = '%(asctime)s %(message)s'
# logging.basicConfig(format=FORMAT)
LOG = logging.getLogger('SNHx')
LOG.setLevel(logging.DEBUG)

class Main(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {
        'wsgi': WSGIApplication
    }

    def __init__(self, *args, **kwargs):
        super(Main, self).__init__(*args, **kwargs)
        print("SNHx is running...")

        # configuration verification error
        if Config.service == 'L2_FABRIC' and Config.forwarding == 'MPLS':
            print('Wrong Configuration: L2_FABRIC + MPLS')
            sys.exit()

        self.thread = {}
        self.thread['cli_thread'] = hub.spawn(self._cli)
        self.thread['routing_thread'] = hub.spawn_after(10 , self._routing)
        self.thread['monitoring_thread'] = hub.spawn_after(10, self._stats_request)

        # run wsgi
        wsgi = kwargs['wsgi']
        wsgi.register(SNHxAPI, {'SNHxAPI': self})

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
        
        dp = event.switch.dp
        print("ada switch mati dengan id", dp.id)

        if dp.id in Collector.topo:
            del Collector.topo[dp.id]
        for src_dpid in Collector.topo:
            if dp.id in Collector.topo[src_dpid]:
                del Collector.topo[src_dpid][dp.id]

        if dp.id in Collector.port_info:
            del Collector.port_info[dp.id]
        if dp.id in Collector.path:
            del Collector.path[dp.id]
        for src_dpid in Collector.path:
            if dp.id in Collector.path[src_dpid]:
                del Collector.path[src_dpid][dp.id]
            for dst_dpid in Collector.path[src_dpid]:
                will_delete = []
                for temp in Collector.path[src_dpid][dst_dpid]:
                    if dp.id in temp.path:
                        will_delete.append(temp)
                Collector.path[src_dpid][dst_dpid] = list(set(Collector.path[src_dpid][dst_dpid]) - set(will_delete))

        if dp.id in Collector.flow_entry:
            del Collector.flow_entry[dp.id]

    # @set_ev_cls(event.EventPortModify)
    # def port_modified_handler(self, event):
    #     port = event.port
    #     LIVE_MSG = {False: 'DOWN', True: 'LIVE'}
    #     print("ada port berubah state di dpid %s port no %s status %s" % (port.dpid,port.port_no,
    #                                                                       LIVE_MSG[port.is_live()]))

    # Event laporan link topo add
    @set_ev_cls(event.EventLinkAdd)
    def add_link(self, event):
        # print('topo discovery received')
        Collector.topo[event.link.src.dpid][event.link.dst.dpid] = LinkDets(event.link.src.dpid,
                                                                            event.link.src.port_no)

    # Event laporan link topo delete
    @set_ev_cls(event.EventLinkDelete)
    def del_link(self, event):
        print('link discovery timeout')

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_handler(self, event):
        msg = event.msg
        dp = msg.datapath
        ofp = dp.ofproto

        if msg.reason == ofp.OFPPR_ADD:
            reason = 'ADD'
            print('port [%s] at dpid[%s] reported with reason %s' % (msg.desc.port_no, dp.id, reason))
            return
        elif msg.reason == ofp.OFPPR_DELETE:
            reason = 'DELETE'
            print('port [%s] at dpid[%s] reported with reason %s' % (msg.desc.port_no, dp.id, reason))
            return
        elif msg.reason == ofp.OFPPR_MODIFY:
            reason = 'MODIFY'
        else:
            reason = 'unknown'
            print('port [%s] at dpid[%s] reported with reason %s' % (msg.desc.port_no, dp.id, reason))
            return

        # self.logger.debug('OFPPortStatus received: reason=%s desc=%s',
        #                   reason, msg.desc)

        # print('OFPPortStatus received: reason=%s desc=%s' % (reason, msg.desc))

        # print('port [%s] at dpid[%s] reported with reason %s' % (msg.desc.port_no, dp.id, reason))
        if msg.desc.port_no not in Collector.port_info[dp.id]:
            return
        if msg.desc.state != Collector.port_info[dp.id][msg.desc.port_no].state:
            Collector.port_info[dp.id][msg.desc.port_no].state = msg.desc.state
            if msg.desc.state:
                print('port [%s] at dpid[%s] is Down' % (msg.desc.port_no, dp.id))
                
                if dp.id in Collector.topo:
                    for dpid_next in Collector.topo[dp.id]:
                        if Collector.topo[dp.id][dpid_next].outPort == msg.desc.port_no:
                            del Collector.topo[dp.id][dpid_next]
                            break

                    if 'dpid_next' not in locals():
                        return

                    for src_dpid in Collector.path:
                        for dst_dpid in Collector.path[src_dpid]:
                            will_delete = []
                            for path_index in range(len(Collector.path[src_dpid][dst_dpid])):
                                if Collector.path[src_dpid][dst_dpid][path_index].path[0] == dpid_next and src_dpid == dp.id:
                                    will_delete.append(Collector.path[src_dpid][dst_dpid][path_index])
                                    continue
                                for per_node_i in range(len(Collector.path[src_dpid][dst_dpid][path_index].path)-1):
                                    if Collector.path[src_dpid][dst_dpid][path_index].path[per_node_i] == dp.id and Collector.path[src_dpid][dst_dpid][path_index].path[per_node_i+1] == dpid_next:
                                        will_delete.append(Collector.path[src_dpid][dst_dpid][path_index])
                                        break
                            Collector.path[src_dpid][dst_dpid] = list(set(Collector.path[src_dpid][dst_dpid]) - set(will_delete))

                    for cookie in Collector.flow_entry[dp.id]:
                        for node_index in range(len(Collector.flow_entry[dp.id][cookie].path)-1):
                            if Collector.flow_entry[dp.id][cookie].path[node_index] == dp.id and \
                               Collector.flow_entry[dp.id][cookie].path[node_index + 1] == dpid_next:
                               req = dp.ofproto_parser.OFPFlowMod(cookie=cookie,
                                                           command=dp.ofproto.OFPFC_DELETE,
                                                           datapath=dp,
                                                           table_id=dp.ofproto.OFPTT_ALL,
                                                           out_port=dp.ofproto.OFPP_ANY,
                                                           out_group=dp.ofproto.OFPG_ANY)
                               Collector.datapaths[Collector.flow_entry[dp.id][cookie].initial_dpid].send_msg(req)


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
            # print('paket ip')

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
            if Config.forwarding == 'IP':
                Forwarding.unicast_internal(datapath, inPort, pkt, msg.data, msg.buffer_id, event)

    def _stats_request(self):

        def send_flow_stats_request(datapath):
            ofp = datapath.ofproto
            ofp_parser = datapath.ofproto_parser

            # cookie = cookie_mask = 0
            # match = ofp_parser.OFPMatch(in_port=1)
            req = ofp_parser.OFPFlowStatsRequest(datapath, 0,
                                                 ofp.OFPTT_ALL,
                                                 ofp.OFPP_ANY, ofp.OFPG_ANY,
                                                 )
            datapath.send_msg(req)

        while True:
            for dpid in Collector.datapaths:
                send_flow_stats_request(Collector.datapaths[dpid])
            hub.sleep(1)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):

        # Get status from a dpid
        dpid = ev.msg.datapath.id
        exist_flow = []
        temp = {}

        # Get status from every cookie which exists
        for stat in ev.msg.body:
            if dpid not in Collector.flow_entry:
                # print('no dpid')
                continue
            if stat.cookie not in Collector.flow_entry[dpid]:
                # print('no cookie')
                continue

            # Record flow which exist
            exist_flow.append(stat.cookie)

            # Update byte.count of Collector.flow_entry
            Collector.flow_entry[dpid][stat.cookie].update_byte_count(stat.byte_count)
 
            # Update upload of Collector.port_info
            out_port = Collector.flow_entry[dpid][stat.cookie].out_port
            bps = Collector.flow_entry[dpid][stat.cookie].bps
            if out_port not in temp:
                temp[out_port] = 0
            temp[out_port] += bps

        for out_port in temp: 
            Collector.port_info[dpid][out_port].upload = temp[out_port]

        entry = []
        for cookie_entry in Collector.flow_entry[dpid]:
            if cookie_entry not in exist_flow:
                entry.append(cookie_entry)

        for will_delete in entry:
            Collector.flow_entry[dpid].pop(will_delete, None)

    def _cli(self):
        Cli.main()
        # Cli_cmd().cmdloop()
        # app_mgr = Main.AppManager.get_instance()
        # app_close()
        # self.routing_thread.kill()
        # self.stop()
        # print("stopping")
        # os.kill()
        # # sys.exit()
        # self.cli_thread.kill()

    def _routing(self):
        print('system is ready')
        while True:
            if Config.forwarding == 'IP':
                Collector.path = DFS.findAllPairsPath(Collector.topo)
                hub.sleep(5)

            elif Config.forwarding == 'MPLS':
                # create topo
                topo = {}
                for src in Collector.topo:
                    topo[src] = {}
                    for dst in Collector.topo[src]:
                        topo[src][dst] = Collector.topo[src][dst].get_cost()

                Collector.path = AllPairsSP.main(topo)

                path = Collector.path
                datapaths = Collector.datapaths
                topo = Collector.topo
                route = Config.route
                MPLSSetup.main(path, datapaths, topo, route)
                
                hub.sleep(60)

class SNHxAPI(RestAPI):
    def __init__(self, req, link, data, **config):
        super(SNHxAPI, self).__init__(req, link, data, **config)
        self.SNHxAPI_spp = data['SNHxAPI']

    # @route('SNHxAPI', '/show-information', methods=['GET'], requirements=None)
    # def get_info(self, req, **kwargs):
    #     message = 'SNHx RestAPI is working'
    #     return Response(status = 200,
    #                     # content_type = 'application/json',
    #                     body = message)