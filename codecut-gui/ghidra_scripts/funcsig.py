# @category CodeCut
from ghidra.program.model.listing import Function
from ghidra.program.model.symbol import SourceType


def get_referenced_function_signatures(program, function_address,
        monitor):
    if function_address is None:
        popup('No address entered')
        return

    function = \
        program.getFunctionManager().getFunctionAt(function_address)
    if function is None:
        popup('No function found at the given address')
        return

    function_signatures = \
        get_referenced_function_signatures_base(function, monitor)

    sigs = '\n/* Refereneced Signatures for: ' + function.getName() \
        + ' */\n'
    for signature in function_signatures:
        sigs += signature

    return sigs


def get_referenced_function_signatures_base(function, monitor):
    if function is None:
        raise ValueError('function is none')

    funcRefs = getFunctionReferences(function, monitor)

    signatures = []
    for refFunc in funcRefs:
        if isUserDefinedFunction(refFunc):
            signatures.append(getFunctionSignature(refFunc) + ';\n')

    return signatures



def getFunctionReferences(function, monitor):
    refs = set()
    instructions = \
        function.getProgram().getListing().getInstructions(function.getBody(),
            True)
    for instr in instructions:
        flowType = instr.getFlowType()
        if flowType.isCall():
            oprefs = instr.getOperandReferences(0)
            if not oprefs: continue
            target = oprefs[0].getToAddress()
            func = function.getProgram().getFunctionManager().getFunctionAt(target)
            if func is not None:
                refs.add(func)
    return refs


def getFunctionSignature(function):
    sig = function.getPrototypeString(False, False)
    return sig


def isUserDefinedFunction(function):
    symbol = function.getSymbol()
    namespace = symbol.getParentNamespace().getName()
    standard_libraries = ['libc', 'libm', 'libpthread', 'libdl', 'std']
    return not any(namespace.startswith(lib) for lib in
                   standard_libraries)

