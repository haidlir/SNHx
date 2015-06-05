from __future__ import print_function

from collector import Collector
import sys, select

def raw_input(message):
    sys.stdout.write(message)

    select.select([sys.stdin], [], [])
    return sys.stdin.readline()

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

    prompt = 'SNH> '
    command_dict = {'show port': print_port_info,\
                    'show topo': print_topo,\
                    'show path': print_path}

    @classmethod
    def main(cls):
        while True:
            command = raw_input(cls.prompt)[:-1:]
            if command == '':
                pass
            elif command == 'halt':
                return False
                break
            elif command in cls.command_dict:
                cls.command_dict[command]()
            else:
                print('command not found')