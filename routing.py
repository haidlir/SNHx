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

    # All Pairs Shortest Path : Floyd Warshal maybe
    @classmethod
    def floyd_warshal_alg(cls, topo):
        past_d = {}
        past_s = {}
        current_d = {}
        current_s = {}

        # init
        past_d = topo
        temp = {}
        for vertex in topo:
            temp[vertex] = vertex

        for vertex in topo:
            past_s[vertex] = temp

        temp = []
        for vertex in topo:
            temp.append(vertex)

        temp_cost = None
        for k in temp:
            for i in past_d:
                if i == k:
                    current_d[i] = past_d[i].copy()
                    current_s[i] = past_s[i].copy()
                    continue
                current_d[i] = {}
                current_s[i] = {}
                for j in temp:
                    if i == j:
                        continue
                    if j == k:
                        if j in past_d[i]:
                            current_d[i][j] = past_d[i][k]
                            current_s[i][j] = past_s[i][k]
                        continue
                    if (k in past_d[i]) and (j in past_d[k]):
                        temp_cost = past_d[i][k] + past_d[k][j]
                        if j not in past_d[i]:
                            current_d[i][j] = temp_cost
                            current_s[i][j] = k
                            continue
                        elif temp_cost < past_d[i][j]:
                            current_d[i][j] = temp_cost
                            current_s[i][j] = k
                            continue
                    if j in past_d[i]:
                        current_d[i][j] = past_d[i][j]
                        current_s[i][j] = past_s[i][j]
            past_d = current_d.copy()
            past_s = current_s.copy()

        return past_d, past_s

    @classmethod
    def s_table_to_path(cls, s_table):
        path = {}
        for i in s_table:
            path[i] = {}
            for j in s_table[i]:
                if i == j:
                    continue
                next_hop = s_table[i][j]
                path[i][j] = [[s_table[i][j]]]
                while next_hop != j:
                    next_hop = s_table[next_hop][j]
                    path[i][j][0].append(next_hop)

        return path

    @classmethod
    def main(cls, topo):
        result_d, result_s = cls.floyd_warshal_alg(topo)
        return cls.s_table_to_path(result_s), result_s

