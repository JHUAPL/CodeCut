#@category CodeCut
#@runtime PyGhidra

from generate_c import generate_recompilable_c_code
import os
from ghidra.util.task import TaskMonitor


def write_c_code_to_file(c_code, output_file_path):
    with open(output_file_path, 'w') as f:
        f.write(c_code)


if __name__ == '__main__':

    args = getScriptArgs()
    start_addr = args[0]
    end_addr = args[1]

    file_name  = args[2]
    output_dir = file_name.rsplit("/", 1)[0] + "/"

    println("Recomp C Range Entry: %s - %s" % (start_addr, end_addr))
    c_code = generate_recompilable_c_code(start_addr, end_addr,
            currentProgram, monitor)

    #file_name = currentProgram.getName()

    #output_dir = askDirectory('Output Directory',
    #                          'Save C code output'
    #                          ).getPath()

    #output_file_path = os.path.join(output_dir, file_name)

    write_c_code_to_file(c_code, file_name)

    println('C code has been saved to %s' % file_name)

