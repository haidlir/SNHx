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

class AllPairsSP(object):

    # All Pairs Shortest Path : Djisktra iterated
    @classmethod
    def SingleSrcSP(cls, topo, src): # Single Source Shortest Path

        unvisited = []
        for vertex in topo:
            if vertex != src:
                unvisited.append(vertex)
        path = [[src]]
        path_cost = {src: 0}

        for i in range(len(unvisited)):
            temp_path = None
            temp_path_cost = None
            temp_cost = None
            for i_path in path:
                for next_vertex in unvisited:
                    if next_vertex not in topo[i_path[-1]]:
                        continue
                    temp_cost = path_cost[i_path[-1]] + topo[i_path[-1]][next_vertex]
                    if (temp_path == None) or temp_path_cost > temp_cost:
                        temp_path_cost = temp_cost
                        temp_path = i_path + [next_vertex]
            if temp_path and temp_path_cost:
                path.append(temp_path)
                path_cost[temp_path[-1]] = temp_path_cost
                unvisited.remove(temp_path[-1])
        return path, path_cost

    @classmethod
    def AllSrcSP(cls, topo): # Single Source Shortest Path
        path = {}
        for src in topo:
            result_path, result_cost = cls.SingleSrcSP(topo, src)
            path[src] = {}
            for dst_path in result_path:
                dst = dst_path[-1]
                if src == dst:
                    continue
                path[src][dst] = [dst_path[1::]]
        return path

    @classmethod
    def main(cls, topo):
        path = cls.AllSrcSP(topo)
        return path

