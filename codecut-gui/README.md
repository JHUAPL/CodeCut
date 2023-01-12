
# Ghidra Plugin for CodeCut GUI

## Building and Installation

Requirements are the same as the Ghidra build requirements, currently JDK 17 (or newer) is required for Ghidra 10.2.

Ghidra's standard Gradle build system is used. Set the `GHIDRA_INSTALL_DIR` environment variable before building, or set it as a Gradle property (useful for building in an IDE).

### Environment Variable 

```
export GHIDRA_INSTALL_DIR="/path/to/ghidra"
gradle 
```

### Gradle property

```
echo GHIDRA_INSTALL_DIR="/path/to/ghidra" > gradle.properties 
```

### Python 3 

The CodeCut GUI's Module Name Guessing tool requires Python 3. Before running the tool, you may need to modify the Python Path of the tool. To do this, **Edit -> Tool Options -> Python Executable**. Insert path to your Python 3 executable. Click apply and ok.

### Install nltk
This module depends on the Python 3 dependency `nltk`. Run the following command to install:
```
pip install nltk
```

### Build Output

The module ZIP will be output to `dist/`. Use **File > Install Extensions** and select the green plus to browse to the extension. Restart Ghidra when prompted.

For proper functionality, the plugin should be built with the same JRE used by your Ghidra installation. if you have multiple Java runtime environments installed, select the correct JRe by setting the `JAVA_HOME` environment variable before building. 

### Running the Plugin

After using **File > Install Extensions** to install the plugin and restarting Ghidra, you may be prompted the next time Ghidra opens to enable the newly-detected plugin. In this case, simply check the box next to **CodeCutGUIPlugin**. 

To enable the plugin normally, you can use **File > Configure...**. Click **Experimental** and check the box next to **CodeCutGUIPlugin**.

Once the plugin is enabled, use **Window > CodeCut Table** to open it. Note that it is intendend to be used after running the **CodeCut** or **DeepCut** analyzers.

Open the CodeCutGUI Window by clicking **Windows->CodeCut Table**. Alternatively use the hot key Ctrl-m.

The Module Name Guessing tool can be started by clicking  **Analysis -> Guess Module Names**.
