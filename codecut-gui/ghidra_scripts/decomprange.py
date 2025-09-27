from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor


def decompile_user_functions_in_range(
    current_program,
    start_address_str,
    end_address_str,
    standard_library_namespaces=None,
    ):
    if standard_library_namespaces is None:
        standard_library_namespaces = ['libc', 'libm', 'libpthread',
                'libdl', 'std']

    def is_user_written_function(function):
        namespace = function.getParentNamespace().getName()
        return namespace not in standard_library_namespaces

    #doesn't quite work right if you have overlapping functions
    #we should rewrite to use FunctionManager/getFunctionsAt functionality
    def getFunctions(start_address, end_address):
        current_addr = start_address
        while current_addr < end_address:
            function = \
                current_program.getFunctionManager().getFunctionContaining(current_addr)
            if function is not None:
                yield function
                current_addr = function.getBody().getMaxAddress().add(1)
            else:
                current_addr = current_addr.add(1)

    start_address = \
        current_program.getAddressFactory().getAddress(start_address_str)
    end_address = \
        current_program.getAddressFactory().getAddress(end_address_str)

    if start_address is None or end_address is None:
        print('Invalid address range specified.')
        return

    if start_address >= end_address:
        print('Invalid address range: start address should be less than end address.')
        return

    decompiler = DecompInterface()
    decompiler.openProgram(current_program)
    monitor = ConsoleTaskMonitor()

    functions = list(getFunctions(start_address, end_address))
    user_written_functions = list(filter(is_user_written_function,
                                  functions))

    decompiled_functions = {}
    for function in user_written_functions:
        decomp_result = decompiler.decompileFunction(function, 0,
                monitor)
        if decomp_result is not None:
            decompiled_functions[function.getName()] = \
                {'address': function.getEntryPoint(),
                 'code': decomp_result.getDecompiledFunction().getC()}

    return decompiled_functions

