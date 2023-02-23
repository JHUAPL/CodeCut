#@category AMP

from std import *

# -------------------------------------------------------------
# Decompile all functions within a range of specified addresses
# -------------------------------------------------------------
# Definitions for decompiler to function
program = getCurrentProgram()
ifc = DecompInterface()
ifc.setOptions(DecompileOptions())
ifc.openProgram(program)

inRangeFunc = []
externFunc  = []
  
# Take user input for address range
args = getScriptArgs()
start_addr = args[0]
end_addr = args[1]

file  = args[2]
path = file.rsplit("/", 1)[0] + "/"

start = int(start_addr, 16)
end = int(end_addr, 16)

def main():
    # Get functions in range of specified addr
    # store functions in range -> inRangeFunc
    # store called functions from in range functions -> externFunc
    getFunctionsInRange(start, end, externFunc, inRangeFunc)
    
    # Decompile in range functions and write to file
    writeToFile(file, externFunc, inRangeFunc)
    
    # Produce "ghidra.h" file
    writeHeader(path)

    # Fix ghidra decompiler access notation
    fixCasting(file)

if __name__ == "__main__":
     main()
