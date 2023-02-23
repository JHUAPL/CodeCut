from ghidra.app.decompiler          import DecompileOptions
from ghidra.app.decompiler          import DecompInterface
from ghidra.util.task               import ConsoleTaskMonitor
from ghidra.program.model.symbol    import RefType,SymbolType
from ghidra.program.model.address   import Address, AddressRange
from ghidra.program.model.lang      import LanguageCompilerSpecPair
from ghidra.program.model.listing   import Program
from ghidra.util                    import Msg
from java.lang                      import IllegalArgumentException
import re
from __main__ import *

# Definitions for decompiler to function
program = getCurrentProgram()
ifc = DecompInterface()
ifc.setOptions(DecompileOptions())
ifc.openProgram(program)

# Standard label list
std = { "_init", "__cxa_finalize", "printf", "_start",
        "deregister_tm_clones", "register_tm_clones", "__do_global_dtors_aux",
        "frame_dummy", "_fini", "__libc_start_main", "_ITM_deregisterTMCloneTable",
        "__gmon_start__", "_ITM_registerTMCloneTable", "__cxa_finalize", "FUN_00101020",
        "puts", "_exit", "_write", "_sbrk", "_read", "_lseek", "_kill", "_isatty", "_gettimeofday",
        "_getpid", "_fstat", "_close", "__clzsi2", "__clzdi2", "__udivmoddi4", "__aeabi_uldivmod",
        "__aeabi_d2iz", "__unorddf2", "__aeabi_dcmpgt", "__aeabi_dcmpge", "__aeabi_dcmple",
        "__aeabi_dcmplt", "__aeabi_dcmpeq", "__aeabi_idivmod", ".divsi3_skip_div0_test",
        "__divsi3", "__aeabi_uidivmod", "__aeabi_uidiv", "FUN_000125c8", "FUN_000123d0", 
        "_getpid_r", "_kill_r", "__sigtramp", "_init_signal", "signal", "raise", "__sigtramp_r",
        "_raise_r", "_signal_r", "_init_signal_r", "abort", "__ascii_wctomb", "_wctomb_r",
        "wcrtomb", "__aeabi_cdcmpeq", "__aeabi_cdrcmple", "__nedf2", "__ledf2", "__gedf2",
        "FUN_00012cec", "__divdf3", "FUN_00012ab8", "__muldf3", "__aeabi_idiv0", "_wcrtomb_r",
        "__swbuf", "__swbuf_r", "strcmp", "_realloc_r", "_read_r", "memmove", "__ascii_mbtowc",
        "_mbtowc_r", "_lseek_r", "setlocale", "__locale_mb_cur_max", "_setlocale_r", "_isatty_r",
        "__sfvwrite_r", "_fstat_r", "fputwc", "_fputwc_r", "__fputwc", "fiprintf", "_fiprintf_r",
        "fclose", "_fclose_r", "_fclose_r", "_close_r", "_calloc_r", "__assert", "__assert_func",
        "_write_r", "__sbprintf", "vfiprintf", "_vfiprintf_r", "__sprint_r", "__sprint_r",
        "strlen", "__sclose", "__sseek", "__swrite", "__seofread", "__sread", "_sbrk_r",
        "_reclaim_reent", "cleanup_glue", "__any_on", "__copybits", "_mprec_log10", "__ratio", "__d2b",
        "__b2d", "__ulp", "__mdiff", "__mcmp", "__lshift", "__pow5mult", "__multiply", "__i2b",
        "__lo0bits", "__hi0bits", "__s2b", "__multadd", "_Bfree", "_Balloc", "__malloc_unlock",
        "__malloc_lock", "memcpy", "memchr", "_malloc_r", "__swhatbuf_r", "__smakebuf_r",
        "localeconv", "_localeconv_r", "__localeconv_l", "_gettimeofday_r", "_fwalk_reent",
        "__sfp_lock_acquire", "__sinit", "_cleanup", "__sfp", "__sfmoreglue", "__sinit",
        "__fp_unlock", "_cleanup_r", "__fp_lock", "fflush", "_fflush_r", "__sflush_r", "_dtoa_r",
        "quorem", "__call_exitprocs", "__register_exitproc", "__swsetup_r", "vfprintf",
        "_vfprintf_r", "time", "rand", "srand", "_printf_r", "memset", "__libc_init_array",
        "__libc_fini_array", "exit", "atexit", "__aeabi_l2d", "__floatundidf", "__aeabi_f2d",
        "__aeabi_i2d", "__floatunsidf", "__aeabi_dadd", "__subdf3", "__aeabi_drsub", "_fwalk",
        "_free_r", "_malloc_trim_r", "__fp_unlock_all", "__fp_lock_all", "__sinit_lock_release",
        "__sinit_lock_acquire", "__sfp_lock_release", "entry", "_stack_init", "register_fini",
        "calloc", "realloc", "__stack_chk_fail", "err", "__printf_chk", "write"}


# Ghidra header file
# Needs to be replaced!! - Placeholder mostly
ghidra_h = """
#ifndef ghidra_h
#define ghidra_h
 
typedef unsigned char byte;   // 8-bit unsigned entity.
typedef byte *        pbyte;  // Pointer to BYTE.
 
// int
typedef unsigned int uint;
typedef int undefined;
typedef int undefined4;
typedef int undefined8;
 
// long
typedef long unsigned int ulong;
typedef long longlong;
// Range
// void
// typedef void undefined;
typedef void void4;
typedef void void8;
#endif
"""

# Fix ghidra casting
def fixCasting(filename): 
    file = open(filename,'r')
    filebuf = file.read()
    pattern = re.compile(r"\b([a-zA-Z0-9._]+)\._(\d{0,4})_(\d{0,4})_")
    matches = pattern.finditer(filebuf)

    file = open(filename,'w')
    for match in matches:
        name = match.group(1)
        offset = match.group(2)
        size = match.group(3)

        if size == "4":
            fixedref = "((int*)" + name + ")[" + offset + "]"
            filebuf = filebuf.replace(match.group(), fixedref)
       
        if size == "1":
            fixedref = "*(uint8_t *)&" + name
            filebuf = filebuf.replace(match.group(), fixedref)
       
    file.write(filebuf)

# Write "ghidra.h" file
def writeHeader(path):
    with open(path+'ghidra.h', 'w') as file:
        file.write(ghidra_h)

# Wrapper function to get address of function offset
def getAddress(offset):
   return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset)

# Get each in range funciton entry point & Functions called by in range functions
# Get each in range funciton entry point & Functions called by in range functions
def getFunctionsInRange(start, end, externFunc, inRangeFunc):
    fm = currentProgram.getFunctionManager()
    programsymbols = fm.getFunctions(True)
    for symbol in programsymbols:
        item = int(symbol.getEntryPoint().toString(), 16)
    
        if item in range(start, end):
            funcName = fm.getFunctionAt(getAddress(item))

            if funcName.getName() not in std:
                print("Found function %s in range" % funcName.getName())
                inRangeFunc.append(funcName.getEntryPoint().toString())
                func = currentProgram.getFunctionManager().getFunctionAt(funcName.getEntryPoint())

                func_list = funcName.getCalledFunctions(getMonitor())
                print(func_list)
                    
                for item in func_list:
                    print(item)
                    #item = item.replace(",", "")
                    if item.getEntryPoint() not in inRangeFunc and item.getName() not in std:
                        externFunc.append(item.getName())


# Wrapper function to write to file
def writeToFile(filename, extern, label):
    file = open(filename,'w')
    # External functions
    print >>file, """#include "ghidra.h"\n"""
    for item in extern:
        print("extern:",item)
        functionList = getGlobalFunctions(item)
        print(functionList)
        if len(functionList) > 0:
            function = functionList[0]
            #if function is not None:
            results = function.getSignature().getPrototypeString()
            results = "extern " + results + ";"
            print("Results:", results)
            print >>file, results

    # Decompiled functions
    for item in label:
        # function = getGlobalFunctions(item)[0]
        function = currentProgram.getFunctionManager().getFunctionAt(getAddress(item))
        results = ifc.decompileFunction(function, 0, ConsoleTaskMonitor())
        filedata = results.getDecompiledFunction().getC()
        file.write(filedata)

    file.close()
