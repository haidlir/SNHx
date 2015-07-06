from __future__ import print_function

from collector import Collector
from lib import OneWayPath

class DFS(object):
    
    @classmethod
    def findAllPairsPath(cls, matrix):
        path = {}
        def findOneSourcePath(now, origin, way = []):
            for i in matrix[now]:
                if i in way or i == origin:
                    continue
                else:
                    if i not in path[origin]:
                        path[origin][i] = [OneWayPath(way + [i], origin)]
                    else:
                        path[origin][i].append(OneWayPath(way + [i], origin))
                    findOneSourcePath(i, origin, way + [i])

        for i in matrix:
            path[i] = {}
            findOneSourcePath(i, i)
        return path

    @classmethod
    def getPath(cls, src_dpid, dst_dpid):
        temp_metric = None
        temp_path = []
        for i in Collector.path[src_dpid][dst_dpid]:
            metric_i = i.get_metric()
            if temp_metric == None:
                temp_metric = metric_i
                temp_path = i.path
            elif temp_metric > metric_i:
                temp_metric = metric_i
                temp_path = i.path
        return temp_path