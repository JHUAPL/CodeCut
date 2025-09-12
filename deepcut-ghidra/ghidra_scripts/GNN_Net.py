# (C) 2022 The Johns Hopkins University Applied Physics Laboratory LLC
# (JHU/APL).  All Rights Reserved.
#
# This material may be only be used, modified, or reproduced by or for
# the U.S. Government pursuant to the license rights granted under the
# clauses at DFARS 252.227-7013/7014 or FAR 52.227-14. For any other
# permission, please contact the Office of Technology Transfer at
# JHU/APL.
#
# NO WARRANTY, NO LIABILITY. THIS MATERIAL IS PROVIDED "AS IS." JHU/APL
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

import torch
import torch.nn.functional as F
from torch.nn import Sequential, Linear, ReLU
from torch_geometric import nn


class Net(torch.nn.Module):
    def __init__(self, num_features, num_edge_features, dim=32):
        super(Net, self).__init__()

        self.init_mlp = Sequential(Linear(num_features, num_edge_features),
                                   ReLU(),
                                   Linear(num_edge_features, num_edge_features))
        self.init_bn = torch.nn.LayerNorm(num_edge_features)

        self.init_emlp = Sequential(Linear(num_edge_features, num_edge_features),
                                    ReLU(),
                                    Linear(num_edge_features, num_edge_features))
        self.init_ebn = torch.nn.LayerNorm(num_edge_features)

        mlp1 = Sequential(Linear(num_edge_features, dim),
                          ReLU(),
                          Linear(dim, dim), ReLU(), Linear(dim, dim))
        self.e_mlp1 = Sequential(Linear(num_edge_features, dim),
                                 ReLU(),
                                 Linear(dim, dim), ReLU(), Linear(dim, dim))
        self.e_bn1 = torch.nn.LayerNorm(dim)
        self.gin1 = nn.GINEConv(mlp1, train_eps=True)
        self.bn1 = nn.PairNorm() # nn.LayerNorm(dim) #torch.nn.BatchNorm1d(dim)

        mlp2 = Sequential(Linear(dim, dim), ReLU(), Linear(dim, dim),
                          ReLU(),
                          Linear(dim, dim))
        self.gin2 = nn.GINEConv(mlp2, train_eps=True)
        self.bn2 = nn.PairNorm()  # nn.LayerNorm(dim) #torch.nn.BatchNorm1d(dim)
        self.e_mlp2 = Sequential(Linear(3*dim, dim),
                                 ReLU(),
                                 Linear(dim, dim),
                                 ReLU(),
                                 Linear(dim, dim))
        self.ebn2 = torch.nn.LayerNorm(dim)

        mlp3 = Sequential(Linear(dim, dim),
                          ReLU(),
                          Linear(dim, dim),
                          ReLU(),
                          Linear(dim, dim))
        self.gin3 = nn.GINEConv(mlp3, train_eps=True)
        self.bn3 = nn.PairNorm()  # nn.LayerNorm(dim)
        self.e_mlp3 = Sequential(Linear(3*dim, dim),
                                 ReLU(),
                                 Linear(dim, dim),
                                 ReLU(),
                                 Linear(dim, dim))
        self.ebn3 = torch.nn.LayerNorm(dim)

        self.out1 = torch.nn.Linear(3*dim, dim)
        self.out_bn = torch.nn.LayerNorm(dim)
        self.out2 = torch.nn.Linear(dim, 4)

    def forward(self, x, edge_attr, edge_index, batch):

        x = F.relu(self.init_mlp(x))
        x = self.init_bn(x)
        edge_attr = self.init_emlp(edge_attr)
        edge_attr = self.init_ebn(edge_attr)

        x = F.relu(self.gin1(x, edge_index, edge_attr))
        x = self.bn1(x, batch)
        edge_attr = F.relu(self.e_mlp1(edge_attr))
        edge_attr = self.e_bn1(edge_attr)

        x = F.relu(self.gin2(x, edge_index, edge_attr))
        x = self.bn2(x, batch)
        edge_attr = torch.cat([x[edge_index[0]], x[edge_index[1]], edge_attr],
                              dim=1)
        edge_attr = self.e_mlp2(edge_attr)
        edge_attr = self.ebn2(edge_attr)

        x = F.relu(self.gin3(x, edge_index, edge_attr))
        x = self.bn3(x, batch)
        edge_attr = torch.cat([x[edge_index[0]], x[edge_index[1]], edge_attr], dim=1)
        edge_attr = self.e_mlp3(edge_attr)
        edge_attr = self.ebn2(edge_attr)  # oops typo this should be a 3

        x = torch.cat([x[edge_index[0]], x[edge_index[1]], edge_attr], dim=1)

        x = F.relu(self.out1(x))
        x = self.out_bn(x)
        x = self.out2(x)

        ret = torch.mean(x, dim=1)

        return ret

def load_gnn(model_file):
    model = Net(
        num_features=2,
        num_edge_features=4,
        dim=64,
    )

    loaded_weights = torch.load(model_file,
                                map_location=torch.device('cpu'),
                                weights_only=True)
    model.load_state_dict(loaded_weights)

    return model
