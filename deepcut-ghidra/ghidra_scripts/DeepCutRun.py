# @category CodeCut
# @menupath CodeCut.DeepCut (Run)
# @toolbar codecut.png
# @runtime PyGhidra

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

import sys
import json

print("started DeepCutRun")


from dependency_bootstrap import DependencyManager

# list the packages you need
# dictionary of "import name" : "pip name"
# for when they differ, e.g. "sklearn": "scikit-learn"
deps = DependencyManager(
    {"networkx": "networkx",
     "scipy": "scipy",
     "torch": "torch",
     "torch_geometric": "torch-geometric"})

# make sure they're installed
if not deps.ensure_or_prompt():
    println("[DeepCut] Required Python packages not available, exiting.")
    exit(1)
    
from deepcut import Deepcut

# Pass Ghidra context + args into your package entry point
# run(currentProgram, state, monitor, *args)

def main():
    args = list(getScriptArgs())
        
    with open(args[0], "r") as f:
        fcg = json.load(f)

    model_path = args[2]
    d = Deepcut(fcg, model_path)
    
    with open(args[1], "w") as f:
        json.dump(d.module_list(), f)
        
    print("Successfully exported module boundaries")

if __name__ == "__main__":
    main()
