from ghidra.program.model.symbol import SourceType
from ghidra.program.model.symbol import SymbolType
from ghidra.program.model.address import AddressSet
#from ghidra.program.flatapi.FlatProgramAPI import getFunctionAt, getDataAt
from ghidra.program.model.data import Array, FloatDataType, \
    DoubleDataType


def get_global_variables(program, start_addr, end_addr):
    global_vars = []
    symbol_table = program.getSymbolTable()
    start_address = \
        program.getAddressFactory().getAddress(start_addr)
    end_address = \
        program.getAddressFactory().getAddress(end_addr)
    addrset = AddressSet(start_address,end_address)
    #set.addRange(start_addr, end_addr)   
    print(start_address, end_address)
    print(addrset)

    #for symbol in symbol_table.getAllSymbols(False):
    for symbol in symbol_table.getSymbols(addrset,SymbolType.LABEL,True):
        print(symbol)
        if (symbol.getSymbolType() == SymbolType.LABEL):
            if (symbol.isGlobal()):          
                if (not program.getListing().getFunctionAt(symbol.getAddress())):
                    if (program.getListing().getDataAt(symbol.getAddress())):
                        global_vars.append(symbol)

	'''
    def is_user_defined(var):
        var_name = var.getName()
        var_addr = var.getAddress()

        if var_name.startswith('__') or var_name.startswith('_'):
            return False

        if var_name.startswith('imp_') or var_name.startswith('thunk_'):
            return False

        if var_name.startswith('fde_') or var_name.startswith('cie_'):
            return False

        if var_name.startswith('completed.0') \
            or var_name.startswith('data_start'):
            return False

        if var_addr.toString().startswith('EXTERNAL:'):
            return False
        section_name = program.getMemory().getBlock(var_addr).getName()
        #if section_name not in ['.data', '.bss']:
        #    return False

        return True
    '''


    #global_vars = list(filter(is_user_defined, global_vars))
    #global_vars = list(filter(is_global_var, global_vars))

    print("G vars first pass:")
    print(global_vars)

    output = '/* Global Variables */\n'
    for var in global_vars:
        var_addr = var.getAddress()
        var_name = var.getName()

        data = program.getListing().getDataAt(var_addr)
        if data is None:
            continue

        dt = data.getDataType()
        dt_name = dt.getDisplayName()
        value = data.getValue()

        pointer_count = 0
        while dt_name.endswith('*'):
            pointer_count += 1
            dt_name = dt_name[:-1].strip()

        if isinstance(dt, Array):
            value = '{' + ', '.join(str(value[i]) for i in
                                    range(len(value))) + '}'
        elif isinstance(dt, FloatDataType) or isinstance(dt,
                DoubleDataType):
            value = '{:.6f}'.format(value)
        elif value is not None:
            value = str(value)
        else:
            value = ''

        output += '{}{} {}{}{};\n'.format(dt_name, (' '
                 if not dt_name.endswith('*') else ''), var_name, '*'
                * pointer_count, (' = {}'.format(value) if value else ''
                ))

    return output

