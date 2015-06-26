from __future__ import print_function

from collector import Collector

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
                        path[origin][i] = [way + [i]]
                    else:
                        path[origin][i].append(way + [i])
                    findOneSourcePath(i, origin, way + [i])

        for i in matrix:
            path[i] = {}
            findOneSourcePath(i, i)
        return path

    @classmethod
    def choosePath(cls, src_dpid, dst_dpid):
        if src_dpid in Collector.path:
            if dst_dpid in Collector.path[src_dpid]:
                return Collector.path[src_dpid][dst_dpid][0]