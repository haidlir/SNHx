from __future__ import print_function
from random import randint

from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.ofproto import ether
from ryu.ofproto import inet
from netaddr.ip import IPNetwork

from collector import Collector
from routing import DFS
from lib import FlowEntry

class Forwarding(object):

    @classmethod
    def unicast_internal(cls, datapath, inPort, pkt, msg_data, buffer_id, event):
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)

        # IP tujuan tidak terdeteksi atau tidak ada
        if pkt_ipv4.dst not in Collector.arp_table:
            return

        src_dpid = datapath.id
        dst_dpid = Collector.arp_table[pkt_ipv4.dst].dpid
        dst_macAddr = Collector.arp_table[pkt_ipv4.dst].mac_addr

        if src_dpid != dst_dpid:
            if src_dpid not in Collector.path:
                return
            if dst_dpid not in Collector.path[src_dpid]:
                return
            if len(Collector.path[src_dpid][dst_dpid]) == 0: # Belum ada routing
                return
            path = [datapath.id] + DFS.getPath(src_dpid, dst_dpid)
        else:
            path = [datapath.id]

        match_dict = {'in_port': 0,
                      'eth_type': ether.ETH_TYPE_IP,
                      'ipv4_src': pkt_ipv4.src,
                      'ipv4_dst': pkt_ipv4.dst,
                      'ip_proto': pkt_ipv4.proto}

        tp_src = tp_dst = 0

        if pkt_ipv4.proto == inet.IPPROTO_TCP:
            pkt_tcp = pkt.get_protocol(tcp.tcp)
            tp_src = match_dict['tcp_src'] = pkt_tcp.src_port
            tp_dst = match_dict['tcp_dst'] = pkt_tcp.dst_port
        elif pkt_ipv4.proto == inet.IPPROTO_UDP:
            pkt_udp = pkt.get_protocol(udp.udp)
            tp_src = match_dict['udp_src'] = pkt_udp.src_port
            tp_dst = match_dict['udp_dst'] = pkt_udp.dst_port

        used = False
        while(not used):
            cookie = randint(0,2**64-1) # ukuran cookie itu 64 bit, dengan all 1s is reserved
            for dpid_cek in Collector.flow_entry:
                if cookie in Collector.flow_entry[dpid_cek]:
                    used = False
                    break
                else:
                    used = True
            if used:
                break

        for index in reversed(range(len(path))):
            actions = []
            # print(index, path[index])
            dp = Collector.datapaths[path[index]]
            if index == len(path)-1:
                actions.append(dp.ofproto_parser.OFPActionSetField(eth_dst=dst_macAddr))
                outPort = Collector.arp_table[pkt_ipv4.dst].port
            else:
                outPort = Collector.topo[path[index]][path[index+1]].outPort
            
            if index == 0:
                match_dict['in_port'] = inPort
            else:
                match_dict['in_port'] = Collector.topo[path[index]][path[index-1]].outPort

            actions += [dp.ofproto_parser.OFPActionOutput(outPort, 0),
                        dp.ofproto_parser.OFPActionDecNwTtl()]
 
            inst = [dp.ofproto_parser.OFPInstructionActions(
                    dp.ofproto.OFPIT_APPLY_ACTIONS, actions)]

            match = dp.ofproto_parser.OFPMatch(**match_dict)


            table_id = 0
            mod = dp.ofproto_parser.OFPFlowMod(
                    cookie=cookie,
                    cookie_mask=0,
                    table_id=table_id,
                    command=dp.ofproto.OFPFC_ADD,
                    datapath=dp,
                    idle_timeout=30,
                    hard_timeout=60,
                    priority=42,
                    # buffer_id=buffer_id,
                    out_port=outPort,
                    out_group=dp.ofproto.OFPG_ANY,
                    match=match,
                    instructions=inst)
            dp.send_msg(mod)

            data = None
            if index == 0:
                if buffer_id == datapath.ofproto.OFP_NO_BUFFER:
                    data = msg_data

                out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=buffer_id,
                                                     in_port=inPort, actions=actions, data=data)
                dp.send_msg(out)

            Collector.flow_entry[path[index]][cookie] = FlowEntry(cookie,\
                                                               table_id,\
                                                               match_dict['ipv4_src'],\
                                                               match_dict['ipv4_dst'],\
                                                               match_dict['ip_proto'],\
                                                               tp_src,\
                                                               tp_dst,\
                                                               match_dict['in_port'],\
                                                               outPort,\
                                                               path)


class MPLSSetup(object):

    label_mapping = {}

    @classmethod
    def main(cls, path, datapaths, topo, route):

        cls.label_mapping = cls.set_label_alloc(datapaths)
        
        for src in path:
            for dst in path[src]:
                if len(path[src][dst]) == 1:
                    complete_path = [src] + path[src][dst][0]
                    print(complete_path)
                    length = len(complete_path)
                    label = cls.label_mapping[dst]
                    dst_prefix = route[complete_path[-1]]
                    for i_node in range(length):
                        if i_node == length-1:
                            continue
                        else:
                            prev_hop = complete_path[i_node]
                            next_hop = complete_path[i_node+1]
                            outPort = topo[prev_hop][next_hop].outPort
                        cls.setup_flow_entry(dst_prefix, label, i_node,
                                             datapaths[complete_path[i_node]],
                                             outPort ,length)

    @classmethod
    def set_label_alloc(cls, datapaths):
        label_mapping = {}
        label_seq = 16
        for dpid in datapaths:
            label_mapping[dpid] = label_seq
            label_seq += 1
        return label_mapping

    @classmethod
    def setup_flow_entry(cls, dst_prefix, label, i_node, datapath, outPort, 
                         length):
        if i_node == 0:
            cls.push_label(dst_prefix, datapath, label, outPort)
        elif i_node == (length-2): # PHP
            cls.pop_label(datapath, label, outPort)
        elif (i_node > 0) and (i_node < (length-2)):
            cls.forward_label(datapath, label, outPort)

    @classmethod
    def push_label(cls, dst_prefix, datapath, label, outPort):
        ipaddress = IPNetwork(dst_prefix)
        dstIp = str(ipaddress.ip)
        dstMask = str(ipaddress.netmask)
        match = datapath.ofproto_parser.OFPMatch(
                eth_type=ether.ETH_TYPE_IP,
                ipv4_dst=(dstIp, dstMask))
        actions =[datapath.ofproto_parser.OFPActionPushMpls(0x8847),
                datapath.ofproto_parser.OFPActionSetField(mpls_label=label),
                datapath.ofproto_parser.OFPActionSetField(mpls_tc=1),
                datapath.ofproto_parser.OFPActionOutput(outPort, 0),
                datapath.ofproto_parser.OFPActionSetMplsTtl(255),
                datapath.ofproto_parser.OFPActionDecMplsTtl()]
        inst = [datapath.ofproto_parser.OFPInstructionActions(
                datapath.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = datapath.ofproto_parser.OFPFlowMod(
                cookie=0,
                cookie_mask=0,
                table_id=0,
                command=datapath.ofproto.OFPFC_ADD,
                datapath=datapath,
                idle_timeout=0,
                hard_timeout=0,
                priority=0xf,
                # buffer_id=0xffffffff,
                out_port=outPort,
                out_group=datapath.ofproto.OFPG_ANY,
                match=match,
                instructions=inst)
        datapath.send_msg(mod)

    @classmethod
    def pop_label(cls, datapath, label, outPort):
        match = datapath.ofproto_parser.OFPMatch(
                eth_type=0x8847,
                mpls_label=label)
        actions =[datapath.ofproto_parser.OFPActionPopMpls(ether.ETH_TYPE_IP),
                datapath.ofproto_parser.OFPActionOutput(outPort, 0),
                datapath.ofproto_parser.OFPActionDecNwTtl()]
        inst = [datapath.ofproto_parser.OFPInstructionActions(
                datapath.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = datapath.ofproto_parser.OFPFlowMod(
                cookie=0,
                cookie_mask=0,
                table_id=0,
                command=datapath.ofproto.OFPFC_ADD,
                datapath=datapath,
                idle_timeout=0,
                hard_timeout=0,
                priority=0xe,
                # buffer_id=0xffffffff,
                out_port=outPort,
                out_group=datapath.ofproto.OFPG_ANY,
                match=match,
                instructions=inst)
        datapath.send_msg(mod)

    @classmethod
    def forward_label(cls, datapath, label, outPort):
        match = datapath.ofproto_parser.OFPMatch(
                eth_type=0x8847,
                mpls_label=label)
        actions = [datapath.ofproto_parser.OFPActionOutput(outPort, 0),
                datapath.ofproto_parser.OFPActionDecMplsTtl()]
        inst = [datapath.ofproto_parser.OFPInstructionActions(
                datapath.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = datapath.ofproto_parser.OFPFlowMod(
                cookie=0,
                cookie_mask=0,
                table_id=0,
                command=datapath.ofproto.OFPFC_ADD,
                datapath=datapath,
                idle_timeout=0,
                hard_timeout=0,
                priority=0xff,
                # buffer_id=0xffffffff,
                out_port=outPort,
                out_group=datapath.ofproto.OFPG_ANY,
                match=match,
                instructions=inst)
        datapath.send_msg(mod)