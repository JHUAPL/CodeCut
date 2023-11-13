from globalvars import get_global_variables
from funcsig import get_referenced_function_signatures
from decomprange import decompile_user_functions_in_range
import re


def fixCasting(code_str):
    pattern = re.compile(r"\b([a-zA-Z0-9._]+)\._(\d{0,4})_(\d{0,4})_")
    matches = pattern.finditer(code_str)

    for match in matches:
        name = match.group(1)
        offset = match.group(2)
        size = match.group(3)

        if size == '4':
            fixedref = '((int*)' + name + ')[' + offset + ']'
            code_str = code_str.replace(match.group(), fixedref)

        if size == '1':
            fixedref = '*(uint8_t *)&' + name
            code_str = code_str.replace(match.group(), fixedref)

    return code_str


def generate_recompilable_c_code(
    start_addr,
    end_addr,
    currentProgram,
    monitor,
    ):
    header_prefix = \
        '''/* Ghidra type resolution */
#include "ghidra.h"

'''

    referenced_funcs = ''
    in_range_c_code = \
        '''

/* Decompiled functions within address range: %s - %s */''' \
        % (start_addr, end_addr)

    global_vars = get_global_variables(currentProgram, start_addr, end_addr)
    print('Global vars:')
    print(global_vars)

    decompiled_functions = \
        decompile_user_functions_in_range(currentProgram, start_addr,
            end_addr)

    for (function_name, function_data) in decompiled_functions.items():
        referenced_funcs += \
            get_referenced_function_signatures(currentProgram,
                function_data['address'], monitor)
        in_range_c_code += function_data['code']

    c_code = header_prefix + global_vars + referenced_funcs \
        + in_range_c_code
    c_code = fixCasting(c_code)
    return c_code

