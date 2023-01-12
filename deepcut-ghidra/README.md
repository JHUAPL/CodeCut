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

### Native Python 3 
The Deepcut graph based machine learning model needs Python 3 to
execute (outside of Ghidra). The analyzer calls an external Python 
process to execute the model on a graph representation of the binary. 
There are no GPU requirements since the model converge quickly even 
running in CPU mode.

#### Python 3 Path
By default the analyzer use the command `/usr/local/bin/python3` to
execute the deepcut python script. This setting can be changed in the
Analysis Options menu **Analysis -> Analyze All Open...** To change the
setting you need to click the checkbox next to **Deepcut (Prototype)**
first.

#### Dependencies
Deepcut has the following Python 3 dependencies:

  - torch 1.7.1
  - torch-geometric 1.6.3
  - torch-cluster 1.5.8
  - torch-sparse 0.6.8
  - torch-scatter 2.0.5
  - torch-spline-conv 1.2.0

To install the dependencies:

```bash
pip install torch==1.7.1+cpu -f https://download.pytorch.org/whl/torch_stable.html
pip install -r requirements-torch_geometric.txt
```

The torch-cluster dependency can take a significant amount of time to
build and install.

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