#!/usr/bin/env python
#
# © 2022 The Johns Hopkins University Applied Physics Laboratory LLC
# (JHU/APL).  All Rights Reserved.
#
# This material may be only be used, modified, or reproduced by or for
# the U.S. Government pursuant to the license rights granted under the
# clauses at DFARS 252.227-7013/7014 or FAR 52.227-14. For any other
# permission, please contact the Office of Technology Transfer at
# JHU/APL.
#
# NO WARRANTY, NO LIABILITY. THIS MATERIAL IS PROVIDED “AS IS.” JHU/APL
# MAKES NO REPRESENTATION OR WARRANTY WITH RESPECT TO THE PERFORMANCE OF
# THE MATERIALS, INCLUDING THEIR SAFETY, EFFECTIVENESS, OR COMMERCIAL
# VIABILITY, AND DISCLAIMS ALL WARRANTIES IN THE MATERIAL, WHETHER
# EXPRESS OR IMPLIED, INCLUDING (BUT NOT LIMITED TO) ANY AND ALL IMPLIED
# WARRANTIES OF PERFORMANCE, MERCHANTABILITY, FITNESS FOR A PARTICULAR
# PURPOSE, AND NON-INFRINGEMENT OF INTELLECTUAL PROPERTY OR OTHER THIRD
# PARTY RIGHTS. ANY USER OF THE MATERIAL ASSUMES THE ENTIRE RISK AND
# LIABILITY FOR USING THE MATERIAL. IN NO EVENT SHALL JHU/APL BE LIABLE
# TO ANY USER OF THE MATERIAL FOR ANY ACTUAL, INDIRECT, CONSEQUENTIAL,
# SPECIAL OR OTHER DAMAGES ARISING FROM THE USE OF, OR INABILITY TO USE,
# THE MATERIAL, INCLUDING, BUT NOT LIMITED TO, ANY DAMAGES FOR LOST
# PROFITS.
#
# HAVE A NICE DAY.

# This material is based upon work supported by the Defense Advanced Research
# Projects Agency (DARPA) and Naval Information Warfare Center Pacific (NIWC Pacific)
# under Contract Number N66001-20-C-4024.


import json
import sys
import numpy as np

import torch

from math import log2, copysign
from networkx import DiGraph
from scipy.linalg import toeplitz

import GNN_Net


class Deepcut:
    def __init__(self, fcg_data, model_file):
        self.fcg_data = fcg_data
        self.model_file = model_file

        self.graph = DiGraph()
        self.functions = {}
        self.graph_connectivity = []
        self.node_features = []
        self.edge_features = []

        self._generate_graph()
        self._generate_features()
        self._predicte_labels()

    def _generate_graph(self):
        for f in self.fcg_data['functions']:
            self.graph.add_node(f['index'],
                                num_inc=log2(2 + f['num_incoming_edges']),
                                num_out=log2(2 + f['num_outgoing_edges']))
            self.functions[f['index']] = {
                'address': f['addr'],
                'name': f['name'],
            }

        for e in self.fcg_data['edges']:
            index_dist_weight = copysign(log2(2 + abs(e['index_distance'])),
                                         e['index_distance'])
            address_dist_weight = copysign(log2(2 + abs(e['addr_distance'])),
                                           e['addr_distance']) / 4
            multiplicity_weight = log2(2 + abs(e['multiplicity']))

            # The weight attribute is a 4-tuple. The multiplicity value
            # is 0.0 for the "opposite" direction
            self.graph.add_edge(e['src_index'], e['dst_index'],
                                weights=(index_dist_weight,
                                         address_dist_weight,
                                         multiplicity_weight,
                                         0.0))

            self.graph.add_edge(e['dst_index'], e['src_index'],
                                weights=(-index_dist_weight,
                                         -address_dist_weight,
                                         0.0,
                                         multiplicity_weight))

    def _generate_features(self):
        for n in sorted(list(self.graph.nodes)):
            self.node_features.append([self.graph.nodes[n]['num_out'],
                                       self.graph.nodes[n]['num_inc']])

        for (n1, n2, d) in self.graph.edges(data=True):
            self.graph_connectivity.append([n1, n2])
            self.edge_features.append(list(d["weights"]))

    def _predicte_labels(self):
        model = GNN_Net.load_gnn(self.model_file)
        m = model(x=torch.Tensor(self.node_features),
                  edge_index=torch.LongTensor(self.graph_connectivity).t().contiguous(),
                  edge_attr=torch.Tensor(self.edge_features),
                  batch=torch.tensor([0] * len(self.graph)))

        self.predicted_labels = torch.sigmoid(m).detach().numpy()

    def _adjacency_matrix(self):
        num_funcs = len(self.graph.nodes)
        A = np.zeros((num_funcs, num_funcs))

        for e, v in zip(self.graph_connectivity, self.predicted_labels):
            e0, e1 = e
            A[e0, e1] = v

        A += A.T
        A *= 0.5

        """
        add a small connection between adjacent nodes,
        essentially to break ties in favor of merging communities
        """
        x = np.zeros(num_funcs)
        x[1] = 0.05
        A += toeplitz(x)

        return A

    def _modularity(self):
        adj_matrix = self._adjacency_matrix()
        # node degrees
        k = np.sum(adj_matrix, axis=0)

        k2 = np.array([k])
        B = k2.T @ k2
        B /= 2 * np.sum(k2)

        Q = adj_matrix - B

        def compute_partial_modularity(start, stop):
            return np.sum(Q[start:stop, start:stop])

        scores = [0.0]
        scores = np.array(scores)
        cuts = [[0]]

        # speedup so it runs in linear time
        max_cluster_size = 100

        for index in range(1, len(self.graph.nodes)):
            update = [compute_partial_modularity(i, index) for i in
                      range(max(0, index-max_cluster_size), index)]
            if index > max_cluster_size:
                update = [0]*(index-max_cluster_size) + update
            updated_scores = scores + update

            i = np.argmax(updated_scores)

            if index > max_cluster_size:
                i = np.argmax(updated_scores[index-max_cluster_size:])+ (index - max_cluster_size)

            s = updated_scores[i]
            c = cuts[i] + [index]

            scores = np.append(scores, s)
            cuts.append(c)

        final_cut = cuts[-1]
        return final_cut

    def module_list(self):
        cuts = self._modularity()
        return [self.functions[x] for x in cuts]


def read_input():
    # Yes this expects the json to have no newlines
    inp = sys.stdin.readline()
    ret = json.loads(inp)
    return ret


def main():
    fcg = read_input()

    if len(sys.argv) == 2:
        model_file = sys.argv[1]
    else:
        model_file = "model_weights_1.p"

    d = Deepcut(fcg, model_file)

    print(json.dumps(d.module_list()))


if __name__ == '__main__':
    main()
