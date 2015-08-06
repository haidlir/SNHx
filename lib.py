from __future__ import print_function
from collector import Collector

def curr_to_capacity(curr):
    capacity = {
      1   : 10.,
      2   : 10.,
      4   : 100.,
      8   : 100.,
      16  : 1000.,
      32  : 1000.,
      64  : 10000.
    }
    return capacity[127 & curr]
    # return 100. # for TC in mininet

class ARPDets(object):
    def __init__(self, dpid, port, mac_addr):
        self.dpid = dpid
        self.port = port
        self.mac_addr = mac_addr

class PortDets(object):
    def __init__(self, index, name, port_no, state, capacity):
        self.index = index
        self.name = name
        self.port_no = port_no
        self.state = state
        self.capacity = capacity
        self.upload = 0 # bps
        self.__name__ = name

    def set_load(self, load = 0):
        self.upload = load

    def _repr__(self):
        return "%s:%s:(%s/%sMbps)" % (self.name, self.port_no, self.upload,
                                                               self.capacity)

class LinkDets(object):
    def __init__(self, dpid, outPort, capacity=100):
        self.dpid = dpid
        self.outPort = outPort
        self.capacity = capacity*(10**6)

    def get_load(self):
        return Collector.port_info[self.dpid][self.outPort].upload
        # return 0

    def get_metric(self):
        return 10.**8/(self.capacity-self.get_load())

    def residual_capacity(self):
        return self.capacity-self.get_load()

    def get_cost(self):
        return 10.**8/self.capacity

    def __repr__(self):
        return "capacity= %s; load = %s; metric = %s" % (self.capacity,
                                                         self.get_load(),
                                                         self.get_metric())

class OneWayPath(object):
    def __init__(self, path, source):
        self.path = path
        self.source = source
        # self.metric = self.calc_metric()

    def get_metric(self):
        temp_metric = 0
        for i in range(len(self.path)):
            if i == 0:
                temp_metric = Collector.topo[self.source][self.path[i]].get_metric()
            else:
                temp_metric += Collector.topo[self.path[i-1]][self.path[i]].get_metric()
        return temp_metric  

    def __repr__(self):
        return "%s --- %s" % (self.path, self.get_metric())

class FlowEntry(object):
    def __init__(self, cookie, table_id, nw_src, nw_dst, nw_proto, tp_src, tp_dst, in_port, out_port, path = [], table = 0, **opts):
        self.cookie = cookie
        self.table_id = table_id
        self.nw_src = nw_src
        self.nw_dst = nw_dst
        self.nw_proto = nw_proto
        self.tp_src = tp_src
        self.tp_dst = tp_dst
        self.in_port = in_port
        self.out_port = out_port
        self.path = path
        if 'dpid' in opts:
            self.initial_dpid = opts['dpid']
        else:
            self.initial_dpid = Collector.arp_table[nw_src].dpid
        self.bps = 0
        self.byte_count = 0
        self.packet_count = 0

    def update_byte_count(self, current_byte_count):
        self.bps = (current_byte_count - self.byte_count) * 8
        self.byte_count = current_byte_count

    def __repr__(self):
        return "%s | %s:%s >%s> %s:%s |%s| %s Bps" % (self.cookie, self.nw_src, self.tp_src,\
                                               self.nw_proto, self.nw_dst, \
                                               self.tp_dst, self.path, self.bps)