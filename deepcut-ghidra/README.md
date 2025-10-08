Ghidra Deepcut Analyzer
=======================

Implementation of Deepcut as a Ghidra one-shot analyzer. 

## Building and Installation
Requirements are the same as Ghidra.  Currently JDK 17 (or newer) is required (for Ghidra 10.2).

Ghidra's standard Gradle build system is used. Set the
`GHIDRA_INSTALL_DIR` environment variable before building, or set it as
a Gradle property (useful for building in an IDE):

### Environment variable
```bash
$ export GHIDRA_INSTALL_DIR="/path/to/ghidra"
$ ./gradle
```

### Gradle property
```bash
echo GHIDRA_INSTALL_DIR=/path/to/ghidra > gradle.properties
```

The module ZIP will be output to `dist/`. Use **File > Install
Extensions** and select the green plus to browse to the
extension. Restart Ghidra when prompted.

For proper functionality, the plugin should be built with the same JRE
used by your Ghidra installation. If you have multiple Java runtime
environments installed, select the correct JRE by setting the
`JAVA_HOME` environment variable before building.

#### ### PyGhidra and Dependencies

DeepCut requires the PyGhidra extension, and is not compatible with Jython. It uses [PyTorch Geometric](https://pytorch-geometric.readthedocs.io/) to perform machine learning on the function call graph. It has the following Python 3 dependencies:
  - torch
  - torch-geometric
  - networkx
  - scipy
DeepCut attempts to automatically install the dependencies when the tool is launched, but they can also be installed using the Python associated with PyGhidra by running:
```bash
pip install torch torch-geometric networkx scipy
```
The torch-geometric dependency can take a significant amount of time to build and install.

## Running the Analyzer
The Deepcut analyzer will not run during auto-analysis. Once the binary
is loaded and the auto-analyzer is finish use the menu item **Analysis
-> One Shot -> Deepcut**

Once complete each function will include a `moduleX` value in the
Namespace field.

If there are any errors please make sure you are using the proper path
to Python 3 and the requirement dependencies installed.

## Troubleshooting
You can verify that dependencies are correct by navigating to:
`~/.ghidra/.ghidra_${VERSION}/Extensions/deepcut-ghidra/data`
and running `./python3 deepcut.py`.  Python will throw errors if it
can't find dependencies.  If the process runs and sits there waiting
for input, then the dependencies should be correct.