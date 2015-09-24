from __future__ import print_function

from ryu.app.wsgi import ControllerBase, route
from webob import Response
import json

from collector import Collector
import sys, select
# import cmd # crash

def raw_input(message):
    sys.stdout.write(message)

    select.select([sys.stdin], [], [])
    return sys.stdin.readline()

def print_flow(s):
    print('detik ke %s' % (s))
    for dpid in Collector.flow_entry:
        print(dpid)
        for cookie in Collector.flow_entry[dpid]:
            print('     %s' % (Collector.flow_entry[dpid][cookie]))
    print('-------------------------------------------------')

class Cli(object):

    def __init__(self, *args, **kwargs):
        super(Tampilan, self).__init__(*args, **kwargs)

    def print_path():
        for i in Collector.path:
            print('source', i)
            for j in Collector.path[i] :
                print('    destination', j)
                for k in Collector.path[i][j]:
                    print('        ',k)

    def print_port_info():
        print(Collector.sw)

    def print_topo():
        print()
        for i in Collector.topo:
            print(i,' = -- ',end='')
            for j in Collector.topo[i]:
                print(j,' ' ,end='')
            print('--')

    def print_arp():
        temp = {}
        print()
        for ip in Collector.arp_table:
            if Collector.arp_table[ip].dpid not in temp:
                temp[Collector.arp_table[ip].dpid] = []
            temp[Collector.arp_table[ip].dpid].append([Collector.arp_table[ip].port,
                                                         ip,
                                                         Collector.arp_table[ip].mac_addr])

        for dpid in temp:
            print(dpid)
            for i in temp[dpid]:
                print('port %s | %s <-> %s' % (i[0], i[1], i[2]))

    def print_port():
        for dpid in Collector.port_info:
            print(dpid)
            print(Collector.port_info[dpid])


    def print_flow():
        for dpid in Collector.flow_entry:
            print(dpid)
            for cookie in Collector.flow_entry[dpid]:
                print('     %s' % (Collector.flow_entry[dpid][cookie]))

    prompt = 'SNHx> '
    command_dict = {'show port': print_port_info,\
                    'show topo': print_topo,\
                    'show path': print_path,\
                    'show arp': print_arp,\
                    'show port': print_port,\
                    'show flow': print_flow}

    @classmethod
    def main(cls):
        while True:
            command = raw_input(cls.prompt)[:-1:]
            if command == '':
                pass
            elif command == 'halt':
                # app_manager.close()
                # sys.exit(0)
                break
            elif command in cls.command_dict:
                cls.command_dict[command]()
            else:
                print('command not found')

class RestAPI(ControllerBase):

    @route('RestAPI', '/show-information', methods=['GET'], requirements=None)
    def get_info(self, req, **kwargs):
        message = 'SNHx RestAPI is working'
        return Response(status = 200,
                        # content_type = 'application/json',
                        body = message)

    @route('RestAPI', '/show-topo', methods=['GET'], requirements=None)
    def get_info(self, req, **kwargs):
        topo = {}
        for src in Collector.topo:
            topo[src] = {}
            for dst in Collector.topo[src]:
                topo[src][dst] = Collector.topo[src][dst].residual_capacity()
        message = json.dumps(topo)
        return Response(status = 200,
                        content_type = 'application/json',
                        body = message)


