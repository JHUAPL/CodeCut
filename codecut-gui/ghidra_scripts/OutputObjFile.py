#@category CodeCut
#@runtime PyGhidra
#
## Copyright 2022 The Johns Hopkins University Applied Physics Laboratory LLC
## (JHU/APL).  All Rights Reserved.
#
## This material may be only be used, modified, or reproduced by or for
## the U.S. Government pursuant to the license rights granted under the
## clauses at DFARS 252.227-7013/7014 or FAR 52.227-14. For any other
## permission, please contact the Office of Technology Transfer at
## JHU/APL.
#
## NO WARRANTY, NO LIABILITY. THIS MATERIAL IS PROVIDED "AS IS." JHU/APL
## MAKES NO REPRESENTATION OR WARRANTY WITH RESPECT TO THE PERFORMANCE OF
## THE MATERIALS, INCLUDING THEIR SAFETY, EFFECTIVENESS, OR COMMERCIAL
## VIABILITY, AND DISCLAIMS ALL WARRANTIES IN THE MATERIAL, WHETHER
## EXPRESS OR IMPLIED, INCLUDING (BUT NOT LIMITED TO) ANY AND ALL IMPLIED
## WARRANTIES OF PERFORMANCE, MERCHANTABILITY, FITNESS FOR A PARTICULAR
## PURPOSE, AND NON-INFRINGEMENT OF INTELLECTUAL PROPERTY OR OTHER THIRD
## PARTY RIGHTS. ANY USER OF THE MATERIAL ASSUMES THE ENTIRE RISK AND
## LIABILITY FOR USING THE MATERIAL. IN NO EVENT SHALL JHU/APL BE LIABLE
## TO ANY USER OF THE MATERIAL FOR ANY ACTUAL, INDIRECT, CONSEQUENTIAL,
## SPECIAL OR OTHER DAMAGES ARISING FROM THE USE OF, OR INABILITY TO USE,
## THE MATERIAL, INCLUDING, BUT NOT LIMITED TO, ANY DAMAGES FOR LOST
## PROFITS.
## HAVE A NICE DAY.
##
## This script takes the boundaries found by deepcut and outputs an object file for the module selected by the user
##
##@author 
##@keybinding 
##@menupath 
##@toolbar 
#@author 
#@category MINDSIGHT
#@keybinding
#@menupath
#@toolbar

import sys, copy, os
import ghidra.app.script.GhidraScript
from ghidra.program.database.module import *
from ghidra.program.flatapi import *
from ghidra.app.services import *
from ghidra.program.model.mem import *
from ghidra.program.model.lang import *
from ghidra.program.model.pcode import *
from ghidra.program.model.util import *
from ghidra.program.model.reloc import *
from ghidra.program.model.data import *
from ghidra.program.model.block import *
from ghidra.program.model.symbol import *
from ghidra.program.model.scalar import *
from ghidra.program.model.listing import *
from ghidra.program.model.address import *
from ghidra.program.util import ProgramLocation
from ghidra.program.database.mem.FileBytes import *
from ghidra.app.util import *
import ghidra.app.util.bin.ByteProvider
import ghidra.util.exception.CancelledException
import ghidra.util.task.TaskMonitor


# Need this line so we can use pyelftools
script_path = parseFile(getSourceFile().getCanonicalPath()).getPath()

pyelftools_path = os.path.join(os.path.dirname(script_path), "pyelftools-0.28")
sys.path.append(pyelftools_path)

# Pyelf imports
from elftools.elf.elffile import ELFFile
from elftools.elf.enums import *

DEBUG = True

# Will hold the symbol table
symtab = None
# Will hold the string table
# The strtab and shstrtab being with \x00
strtab = []
# Will hold the section header string table
shstrtab = '\x00'

# Will hold all sections
sections = []
NUM_SECTIONS = 0 # Total number of sections

# Number of relocations
NUM_RELOCS = 0
# Size of relocation fields
RELOC_SIZE = 8

# relocations contains a nested dictionary containing details about the functions in the module
# It contains the name of all functions it called as well as the address those functions were called
relocations = {}

# Dictionary of all symbols in the module
# mapping is LOCAL: [list of local symbols], GLOBAL: [list of global symbols]
symbols = {}
symbols['LOCAL'] = []
symbols['GLOBAL'] = []
data_symbols = []

# These will take up an entry in the symbol table
section_symbols = ['null', '.text', '.rodata', '.data', '.bss']

required_sections = ['.text', '.rel.text', '.data', '.bss', '.symtab', '.strtab', '.shstrtab']

# Total number of symbols
total_symbols = len(section_symbols)

# The number of entries in the rodata section
rodata_entries = 0

bss_fragment = None
data_fragment = None
rodata_fragment = None

"""
Symbol Table Entry
typedef struct {
    Elf32_Word st_name;     (4 bytes)
    Elf32_Addr st_value;    (4 bytes)
    Elf32_Word st_size;     (4 bytes)
    unsigned char st_info;  (1 byte)
    unsigned char st_other; (1 byte)
    Elf32_Half st_shndx;    (2 bytes)
} Elf32_Sym;                (16 bytes total)
"""
SYM_SIZE = 16 # Size of symbols in symtab section
 
"""
Elf Header
typedef struct {
    unsigned char e_ident[EI_NIDENT]; (16 bytes)
    Elf32_Half e_type;                (2 bytes)
    Elf32_Half e_machine;             (2 bytes)
    Elf32_Word e_version;             (4 bytes)
    Elf32_Addr e_entry;               (4 bytes)
    Elf32_Off e_phoff;                (4 bytes)
    Elf32_Off e_shoff;                (4 bytes)
    Elf32_Word e_flags;               (4 bytes)
    Elf32_Half e_ehsize;              (2 bytes)
    Elf32_Half e_phentsize;           (2 bytes)
    Elf32_Half e_phnum;               (2 bytes)
    Elf32_Half e_shentsize;           (2 bytes)
    Elf32_Half e_shnum;               (2 bytes)
    Elf32_Half e_shstrndx;            (2 bytes)
 } Elf32_Ehdr;                        (52 bytes total)
"""
ELFHDRSZ = 52 # size of the ELF header

"""
typedef struct {
    Elf32_Word sh_name;                (4 bytes)
    Elf32_Word sh_type;                (4 bytes)
    Elf32_Word sh_flags;               (4 bytes)
    Elf32_Addr sh_addr;                (4 bytes)
    Elf32_Off sh_offset;               (4 bytes)
    Elf32_Word sh_size;                (4 bytes)
    Elf32_Word sh_link;                (4 bytes)
    Elf32_Word sh_info;                (4 bytes)
    Elf32_Word sh_addralign;           (4 bytes)
    Elf32_Word sh_entsize;             (4 bytes)
} Elf32_Shdr;                          (40 bytes total)
"""
SHSIZE = 40 # size of section headers
OFFSET = 0 # Offset into the file
moduleName = ''
elffile = None
minModuleAddress = None
maxModuleAddress = None
moduleBytes = bytearray()
rodata_bytes = bytearray()
mod = None
alignment = 4

# These sections are specific to an executable binary. Relocatable object files don't need these
exclude_sections = ['.init', '.fini', '.eh_frame', '.stab', '.debug', '.noinit', '.exidx', '.got',
                    '__', '.rel.ro', 'plt', 'dyn']


def SelectModule(module=""):
    global moduleName, minModuleAddress, maxModuleAddress, prog, mod, ns

    # Check if there is a program open
    if (currentProgram == None):
        popup("There is no open program")
        return False
        
    # Get Program
    prog = currentProgram
    
    # Get the symbol table
    st = prog.getSymbolTable()
    SymbolIterator = st.getAllSymbols(True)
    if module == "":
        Modulelist = {}
        # This loop attempts to get all modules (namespaces) within this program
        while(SymbolIterator.hasNext()):
            sym = SymbolIterator.next()
            ns = sym.getParentNamespace()
            # Want to get any namespace that isn't global or external
            # These are likely namespaces that were created by deepcut
            if (ns.getName() == u"Global") or (ns.getName() == u"<EXTERNAL>"):
                continue
            if (ns not in Modulelist):
                Modulelist[ns.getName()] = ns
        # There weren't any namespaces found
        if not Modulelist:
            popup("There doesn't seem to be any modules created by DeepCut (Namespaces is empty?).\nPlease run the DeepCut Analyzer before running this script.\nFor additional fidelity run GuessModuleNames from the CodeCut GUI.")
            return False
        else:
            # Ask user for module to export as object file
            Modulechoice = askChoice("Select a Module", getCategory(), Modulelist.keys(), None);
    
            print(Modulechoice + " was chosen!\n")
            moduleName = Modulechoice
            
            # Get min and max address of selected namespace
            # getBody() returns an AddressSetView which can be used to get the min and max address of the namespace
            mod = Modulelist[Modulechoice]
            asv = mod.getBody()

    else:
        moduleName = module
        mod = st.getNamespace(module, prog.getGlobalNamespace())
        if mod:
            asv = mod.getBody()
            println("Module: %s" % mod.getName())
        else:
            popup("Something went wrong. %s doesn't seem to be a valid module..." % mod.getName())
            return False
        
    # Get the minimum and maximum address for the module
    minModuleAddress = asv.getMinAddress()
    maxModuleAddress = asv.getMaxAddress()
        
    # This module is not valid
    if minModuleAddress == None or maxModuleAddress == None or (minModuleAddress == maxModuleAddress):
        popup("The module you selected is invalid. This could be the min and/or max Address do not exist or the min and max address of the module are equal to each other. Please select another module")
        return False
    else:
        newMax = maxModuleAddress
        # It's possible that the max module address does not include the 
        # entirety of the module. This is meant to adjust the max boundary
        # so every byte within the module is accounted for.
        while not getFunctionAt(newMax.add(1)):
            maxModuleAddress = maxModuleAddress.add(1)
            newMax = maxModuleAddress
            

        println("Min module address: %s" % (str(minModuleAddress)))
        println("Max module address; %s" % (str(maxModuleAddress)))
        return True
        
                
def get_symbols():
    global minModuleAddress, maxModuleAddress, mod, symbols, bss_fragment, data_fragment, rodata_fragment, rodata_entries
    # Get the symbol table
    st = prog.getSymbolTable()
    listing = prog.getListing()
    bss_fragment = listing.getFragment("Program Tree", ".bss")
    data_fragment = listing.getFragment("Program Tree", ".data")
    rodata_fragment = listing.getFragment("Program Tree", ".rodata")
    
    definedData = listing.getDefinedData(rodata_fragment.getMinAddress(), True)

    
    # Grab all symbols
    SymbolIterator = st.getAllSymbols(True)
    # This loop grabs all symbols referenced by the module, both internal symbols and external symbols
    # External symbols are symbols that are referenced by an internal function but the address is 
    # outside the boundary of the module. For example, if the min and max address is 800000-900000,
    # at some point a function within the module referenced a symbol whose address is greater than 900000
    # or less than 800000. Internal symbols are those whose address fall within the boundary of the 
    # min and max address.
    while SymbolIterator.hasNext():
        sym = SymbolIterator.next()
        
        # TODO: Make this more elegant
        if "_init" in sym.getName() or "_fini" in sym.getName() or "_start" in sym.getName():
            continue
        # We only want ones that were imported (symbols in the .bss_fragment section seem to land in this category)
        if (sym.getSource().getDisplayString() == 'Imported') or (sym.getSource().getDisplayString() == 'User Defined'):
            # Check if symbol has references
            if sym.hasMultipleReferences() or sym.hasReferences():
                symRef = sym.getReferences()
                for ref in symRef:
                    # Are those references in the module?
                    if isInternalSymbol(ref):
                        # Is this symbol in the data or bss section? If yes it's a local symbol
                        if (bss_fragment.contains(sym.getAddress()) or data_fragment.contains(sym.getAddress())) and \
                            sym not in symbols['LOCAL']:
                            println("Adding symbol: %s Address: %s Reference: %s" % (sym.getName(), sym.getAddress(), ref.getFromAddress()))
                            symbols['LOCAL'].append(sym)
                        if sym.getSymbolType().toString() == 'Function' and \
                            sym not in symbols['GLOBAL']:                                  
                                symbols['GLOBAL'].append(sym)
            # The symbol is in the bss or data section and didn't have any references but it's address is within the module boundaries 
            if (bss_fragment.contains(sym.getAddress()) or data_fragment.contains(sym.getAddress())) and \
                sym not in symbols['LOCAL'] and \
                (isInternalSymbol(sym)):
                println("Adding symbol: %s Address: %s" % (sym.getName(), sym.getAddress()))
                symbols['LOCAL'].append(sym)
            # The symbol didn't have any references
            if sym not in symbols['GLOBAL']:
                if isInternalSymbol(sym):
                    symbols['GLOBAL'].append(sym)
        else:
            continue
    
    # Defined strings need to be relocated but they aren't necessarily symbols
    # We add them to our symbol dictionary here but we will need to subtract the number of symbols we add
    # here to the total number of symbols. Additionally, when writing the symtab section
    # we'll need to ensure we don't write these symbols.
    for dat in definedData:
        refs = dat.getReferenceIteratorTo()
        if rodata_fragment.contains(dat.getAddress()):
            for ref in refs:
                if isInternalSymbol(ref):
                    symbols['LOCAL'].append(dat)
                    rodata_entries += 1
                    break
                else:
                    continue

    print("Global and local symbols: ", symbols)
    maxModAddress = update_functions()
    # Updating maxModuleAddress just in case it changed in update_functions
    if maxModAddress.subtract(maxModuleAddress) > 0:
         maxModuleAddress = maxModAddress
    println("Minimum Module Address: %s" % minModuleAddress)
    println("Maximum Module Address: %s" % maxModuleAddress)


"""
    This function checks if the symbol is internal to the current module
    @param symbol: The symbol we want to determine is internal or external
    @return: True if the symbol is internal; false otherwise
"""
def isInternalSymbol(symbol):
    
    # Check if reference is within module
    if "reference" in str(type(symbol)).lower():
        if symbol.getFromAddress().compareTo(minModuleAddress) >= 0 and \
            symbol.getFromAddress().compareTo(maxModuleAddress) <= 0:
            return True
        else:
            return False
    # Check if symbol is within module
    elif symbol.getAddress().compareTo(minModuleAddress) >= 0 and \
        symbol.getAddress().compareTo(maxModuleAddress) <= 0:
        return True
    else:
        return False

def update_functions():
    # This is the current upward bounds of the module
    # It's possible this will not change so we save it here
    newMaxAddress = maxModuleAddress
    for sym in symbols['GLOBAL']:
        if isInternalSymbol(sym):
            if sym.getSymbolType().toString() == 'Function':
                println("Symbol name: %s\n" % sym.getName())
                func = getFunctionAt(sym.getAddress())
                funcBody = func.getBody()
                maxAddr = funcBody.getMaxAddress()
                println("Max address: %s" % (str(maxAddr)))
    
                newMax = maxAddr
                # Currently, Ghidra does not include all bytes for function that include data elements
                # We're accounting for this by checking if the next byte is a new function
                # If it is a new function then Ghidra already has the proper function size. If not,
                # than Ghidra will misrepresent the size of the function leading to incorrect processing
                # later on.
                while not getFunctionAt(newMax.add(1)):
                    maxAddr = maxAddr.add(1)
                    newMax = maxAddr
                println("newMax: %s" % (str(newMax)))
    
                # The previos loop resulted in a new maximum address for the current function
                # Let's update the function to include the new bytes
                if newMax.subtract(funcBody.getMaxAddress()) > 0:
                    println("Need to update the address set for this function\n")
                    # Build an address set using the entry point for the function 
                    # and the new max address
                    newAddrSet = AddressSet(sym.getAddress(), newMax)
                    # Modify the body to include the new address set
                    func.setBody(newAddrSet)
    
                    # println("newMax - newMaxAddress: %d" % newMax.subtract(newMaxAddress))
                    # This check probably isn't completely necessary. Before entering this function we already 
                    # modified the boundary for the module. However, there is still a chance that 
                    # there are some new bytes not accounted for. We check if the new address is greater
                    # than the address we already have for the module boundary. If it is greater than we 
                    # update the maximum address, otherwise we continue on
                    if newMax.subtract(newMaxAddress) > 0:
                        println("Updating module boundary!")
                        newMaxAddress = newMax
                    else:
                        continue
                    
                else:
                    println("This function is fine")
    return newMaxAddress
    
"""
    Taken from https://stackoverflow.com/a/20793663
    Python 2.7 does not have a to_bytes method for integers :(
    @param n: The number to convert to bytes
    @param length: How many bits should be used to represent the integer
    @param endianess: What endianess should be used? Supports little and big endian
"""
def to_bytes(n, length, endianess='little'):
    h = '%x' % n
    s = '{:0{}x}'.format(n, length*2).decode('hex')
    return s if endianess == 'big' else s[::-1]

"""
    This function writes the ELF header to a file object. A lot of the entries in the ELF header 
    are unchanged or only slightly modified. Each entry is commented out and any changes are 
    called out with a reason for the change
    @param obj_file: The new object file being created.
    @param elffile: The elffile object of the current ELF file being analyzed.
    @var ENUM: The ENUM_X_YYYY are enumerations used by the pyelftools library. 
"""
def write_elf_header(obj_file):
    
    println("Writing the ELF Header!")
    # Write the raw e_ident field to the file
    # This should not change in any considerable way so just copy the field
    # from the original ELF executable
    obj_file.write(elffile.e_ident_raw)
    
    # The next byte is going to determine the type of file (i.e. executable or relocatable)
    # The pyelftools library enumerates lots of useful ELF values 
    obj_file.write(to_bytes(ENUM_E_TYPE['ET_REL'], 2, 'little'))
    
    
    # Now let's write the machine type
    obj_file.write(to_bytes(ENUM_E_MACHINE[elffile.header['e_machine']], 2, 'little'))
    
    # Write the version
    obj_file.write(to_bytes(ENUM_E_VERSION['EV_CURRENT'], 4, 'little'))
    
    # Write the entry point
    # This will be zero since it's an object file
    e_entry = 0
    obj_file.write(to_bytes(e_entry, 4, 'little'))
    
    # Write start of program headers:
    # This will be zero since an object file does not have program headers
    e_phoff = 0
    obj_file.write(to_bytes(e_phoff, 4, 'little'))
    
    # Start of section headers
    # This member holds the section header table's file offset in bytes
    # For simplicity, I place the section header table immediately after the 
    # end of the last section written
    e_shoff = OFFSET
    println("Section Header Offset: %d" % e_shoff)
    obj_file.write(to_bytes(e_shoff, 4, 'little'))
    
    # Write flags
    obj_file.write(to_bytes(elffile.header['e_flags'], 4, 'little'))
    
    # Write Header Size
    # The header size should always be the same
    obj_file.write(to_bytes(elffile.header['e_ehsize'], 2, 'little'))
    
    # Write program header size
    e_phentsize = 0 # No program headers in a relocatable object file
    obj_file.write(to_bytes(e_phentsize, 2, 'little'))
    
    # Write Number of program headers
    e_phnum = 0
    obj_file.write(to_bytes(e_phnum, 2, 'little'))
    
    # Write size of section headers
    obj_file.write(to_bytes(elffile.header['e_shentsize'], 2, 'little'))
    
    # Write number of section headers
    e_shnum = NUM_SECTIONS
    println("Number of section: %d" % NUM_SECTIONS)
    obj_file.write(to_bytes(e_shnum, 2, 'little'))
    
    # Write Section header string table index
    e_shstrndx = [i for i,v in enumerate(sections) if v.name == '.shstrtab'][0]
    obj_file.write(to_bytes(e_shstrndx, 2, 'little'))


"""
    This function writes the section header data to the newly created object file
    It takes a section that may have been modified.
    @param obj_file: A file descriptor representing the new object file being created
    @param section: A section in the ELF file
"""
def write_section_headers(obj_file, section):
    
    println("Writing section header: %s" % section.name)
    # Write sh_name
    obj_file.write(to_bytes(section.header['sh_name'], 4, 'little'))
    
    # Write sh_type
    obj_file.write(to_bytes(ENUM_SH_TYPE_ARM[section.header['sh_type']], 4, 'little'))
    
    # Write sh_flags
    obj_file.write(to_bytes(section.header['sh_flags'], 4, 'little'))
    
    # Write sh_addr
    obj_file.write(to_bytes(section.header['sh_addr'], 4, 'little'))
    
    # Write sh_offset
    obj_file.write(to_bytes(section.header['sh_offset'], 4, 'little'))
    
    # Write sh_size
    obj_file.write(to_bytes(section.header['sh_size'], 4, 'little'))
    
    # Write sh_link
    obj_file.write(to_bytes(section.header['sh_link'], 4, 'little'))
    
    # Write sh_info
    obj_file.write(to_bytes(section.header['sh_info'], 4, 'little'))
    
    # Write sh_addralign
    obj_file.write(to_bytes(section.header['sh_addralign'], 4, 'little'))
    
    # Write sh_entsize
    obj_file.write(to_bytes(section.header['sh_entsize'], 4, 'little'))
        
"""
    This function gets the size of the data, rodata, or bss sections. Since these sections size depend 
    on the presence of variables or defined strings, it's possible the size will be either zero or 
    the sum of all data that resides in their repsective sections
    @param section: The section we want to calculate the size
    @return: The size of the section or zero if it has no size
""" 
def get_section_size(section):
    global rodata_bytes
    if section == '.bss':
        bss_section_size = 0
        for sym in symbols['LOCAL']:
            if bss_fragment.contains(sym.getAddress()):
                dat = getDataAt(sym.getAddress())
                bss_section_size += dat.getLength()
        println("bss_section_size: %d" % bss_section_size)
        return bss_section_size
    elif section == '.data':
        data_section_size = 0
        for sym in symbols['LOCAL']:
            if data_fragment.contains(sym.getAddress()):
                println("Name: %s" % sym)
                dat = getDataAt(sym.getAddress())
                if dat.getLength() % alignment != 0:
                    diff = (alignment - (dat.getLength() % alignment))
                    size = diff + dat.getLength()
                else:
                    size = dat.getLength()
                data_section_size += size
        println("data_section_size: %d" % data_section_size)
        return data_section_size
    else:
        return 0

"""
    This function performs any necessary modifications to the section headers. Only 
    the .text, .data, .rodata, .bss, .strtab, .shstrtab, and .symtab require specific
    modifications. This is because these sections are likely to change from the executable.
    For example, the .text section is going to be MUCH smaller in the unlinked object file compared
    to the full executable file because there's far less code. This is similar for the other sections.
    The other section headers, only the sh_offset and sh_name field will be changed since we copy the 
    data from those sections directly to our new unlinked object file.
    Here is a description of the fields and how they will be modified and how they are created:
    sh_name
       This field is an index into the string table
       section['sh_name'] = strtab.find(section.name)
    
    
    sh_size
        This is the size of the section. For the .text section it's simply the size of the moduleBytes variable.
        For .data and .bss the size is a sum of the size of all variables in the respective section. For example, 
        if the .data section has two integers and a char, the size of this section would be 9 (sizeof(int) + sizeof(int) + sizeof(char))
        The .rodata section is simply the length of all strings in the section. For example, if the .rodata section contained only one
        string ("I am in the .rodata section"), the size would be len("I am in the .rodata section")
        Currently, the size for these sections are set to zero, but an update will come to provide accurate sizes if necessary. The
        .rel.text section's size is (number of relocations * size of each relocation). In our case the size of each relocation is 8 bytes.
        Similarly, .symtab section's size is the (number of symbols * symbol size), where the size of each symbol is 16 bytes.
        
    sh_offset
        This is the offset of where the section data is in the file. For example, if the data for .rel.text section begins 128 bytes into the 
        file, this field will be hex(128)
    
    sh_info
        The sh_info field for .rel.text holds the index for the .text section. For the .symtab section, this field holds the symbol index 
        for the first non-local symbol. In our unlinked object file, the index should always going to be one. Therefore, it's hard coded.
        In the future I'd like to avoid hardcoding this value.
        For the .rel.text section, I update this field using the following statement:
        [j for j,v in enumerate(sections) if v.name == '.text'][0]
        The sections variable is a list that contains pyelftools section objects. This would grab the index where the '.text' section
        resides.

    sh_link
        This field is only relevant for the .rel.text section and the .symtab section. For the .rel.text section, this field represents
        the index of the symbol table section. Given that the .rel.text section handles relocations, it makes sense why this section 
        would need a link to the symbol table. For the .symtab section, this field represents the index for the string table. Again,
        because symbol's in the .symtab section don't contain names but indices into the .strtab section, it makes sense why this section
        needs a link to the string table section.
        This field is updated using a similar statement to the sh_info field.
        For .rel.text we use:
        [j for j,v in enumerate(sections) if v.name == '.symtab'][0] + 1
        We add one here because we're assuming the executable does not have a .rel.text section and it needs to be added. Because we're
        adding a section, the index of the .symtab section will be incremented by one.
        For .symtab we use
        [j for j,v in enumerate(sections) if v.name == '.strtab'][0] + 1
    
    sh_addr
        This is the address at which the section's first byte should reside in memory. Since this is a relocatable object file, this 
        field can safely be hardcoded to zero.

"""
def modify_section_headers():
    
    global OFFSET, section_symbols, rodata_entries
    # The offset will be accumulated
    # The initial offset for the sections will be the size of the 
    # ELF Header because that's where we'll begin writing section our data
    OFFSET = ELFHDRSZ
    if DEBUG:
        println("----------------------------- Modifying section headers --------------------------------")
    for i, section in enumerate(sections):
        if DEBUG:
            println("Number of section: %d" % len(sections))
            println("Section name: %s OFFSET: %d" % (section.name, OFFSET))
            println("Index: %d section name: %s" % (i, sections[i].name))
         
        if section.name == '.text':
            sections[i].header['sh_name'] = shstrtab.find(section.name)
            sections[i].header['sh_size'] = len(moduleBytes)
            sections[i].header['sh_addr'] = 0 # All section headers will have addr set to zero
            sections[i].header['sh_offset'] = OFFSET
            sections[i].header['sh_addralign'] = 4
            OFFSET += sections[i].header['sh_size'] # Update offset for next section header
            if DEBUG:
                println("%s size: %d Section Offset: %d" % (section.name, sections[i].header['sh_size'], sections[i].header['sh_offset']))
                println("OFFSET: %d" % OFFSET)

        elif section.name == '.rel.text':
            section.header['sh_offset'] = OFFSET
            section.header['sh_name'] = shstrtab.find('.rel.text')
            section.header['sh_type'] = 'SHT_REL'
            section.header['sh_addr'] = 0
            section.header['sh_flags'] = 0x40
            section.header['sh_size'] = NUM_RELOCS * RELOC_SIZE
            section.header['sh_entsize'] = 0x8
            section.header['sh_link'] = [i for i,v in enumerate(sections) if v.name == '.symtab'][0]
            section.header['sh_info'] = [i for i,v in enumerate(sections) if v.name == '.text'][0]
            section.header['sh_addralign'] = 4
            OFFSET += section.header['sh_size']
            if DEBUG:
                println("%s size: %s Section Offset: %d Num Relocaions: %d" % (section.name, section.header['sh_size'], section.header['sh_offset'], NUM_RELOCS))
                println("OFFSET: %d" % OFFSET)
            
        elif section.name == '.symtab':
            sections[i].header['sh_name'] = shstrtab.find(section.name)
            sections[i].header['sh_size'] = total_symbols * SYM_SIZE
            sections[i].header['sh_addr'] = 0
            # The sh_info section points to the first non local symbol in the symbol table. 
            # In order to get this we take the section symbols (which are local) and all 
            # local symbols we found earlier and subtract that from the rodata entries that may be 
            # present. 
            sections[i].header['sh_info'] = len(section_symbols) + (len(symbols['LOCAL']) - rodata_entries)
            sections[i].header['sh_link'] = [j for j,v in enumerate(sections) if v.name == '.strtab'][0]
            sections[i].header['sh_offset'] = OFFSET
            sections[i].header['sh_addralign'] = 4
            OFFSET += sections[i].header['sh_size'] # Update offset for next section header
            if DEBUG:
                println("%s size: %d Section Offset: %d Total Symbols: %d" % (section.name, sections[i].header['sh_size'], sections[i].header['sh_offset'], total_symbols))
                println("OFFSET: %d" % OFFSET)

        elif section.name == '.strtab':
            sections[i].header['sh_name'] = shstrtab.find(section.name)
            sections[i].header['sh_size'] = len(strtab)
            sections[i].header['sh_offset'] = OFFSET
            sections[i].header['sh_addr'] = 0
            sections[i].header['sh_addralign'] = 1
            OFFSET += sections[i].header['sh_size']
            if DEBUG:
                println("%s size: %d Section Offset: %d" % (section.name, sections[i].header['sh_size'], sections[i].header['sh_offset']))
                println("OFFSET: %d" % OFFSET)

        elif section.name == '.shstrtab':
            sections[i].header['sh_name'] = shstrtab.find(section.name)
            sections[i].header['sh_size'] = len(shstrtab)
            sections[i].header['sh_offset'] = OFFSET
            sections[i].header['sh_addr'] = 0
            sections[i].header['sh_addralign'] = 1
            OFFSET += sections[i].header['sh_size']
            if DEBUG:
                println("shstrtab: %s length: %d" % (shstrtab, len(shstrtab)))
                println("section %s size: %d Section Offset: %d" % (section.name, sections[i].header['sh_size'], sections[i].header['sh_offset']))
                println("OFFSET: %d" % OFFSET)

        elif section.name == '.rodata':
            sections[i].header['sh_name'] = shstrtab.find(section.name)
            sections[i].header['sh_size'] = len(rodata_bytes) # Size will be sum of length all strings in rodata section
            sections[i].header['sh_offset'] = OFFSET
            sections[i].header['sh_addr'] = 0
            sections[i].header['sh_addralign'] = 4
            OFFSET += sections[i].header['sh_size']
            if DEBUG:
                println("rodata: %s length: %d" % (rodata_bytes, len(rodata_bytes)))
                println("%s size: %d Section Offset: %d" % (section.name, sections[i].header['sh_size'], sections[i].header['sh_offset']))
                println("OFFSET: %d" % OFFSET)

        elif section.name == '.data':
            sections[i].header['sh_name'] = shstrtab.find(section.name)
            sections[i].header['sh_size'] = get_section_size(section.name) # Size will be sum of all data element's size (i.e. sizeof (int) + sizeof(char) + sizeof(int), assuming there are two integers and a char in the .data section)
            sections[i].header['sh_offset'] = OFFSET
            sections[i].header['sh_addr'] = 0
            sections[i].header['sh_addralign'] = 4
            OFFSET += sections[i].header['sh_size']
            if DEBUG:
                println("%s size: %d Section Offset: %d" % (section.name, sections[i].header['sh_size'], sections[i].header['sh_offset']))
                println("OFFSET: %d" % OFFSET)

        elif section.name == '.bss':
            sections[i].header['sh_name'] = shstrtab.find(section.name)
            sections[i].header['sh_size'] = get_section_size(section.name) # Size will be sum of all data element's size (i.e. sizeof (int) + sizeof(char) + sizeof(int), assuming there are two integers and a char in the .data section)
            sections[i].header['sh_offset'] = OFFSET
            sections[i].header['sh_addr'] = 0
            sections[i].header['sh_addralign'] = 1
            if DEBUG:
                println("%s size: %d Section Offset: %d" % (section.name, sections[i].header['sh_size'], sections[i].header['sh_offset']))
                println("OFFSET: %d" % OFFSET)
            # The bss section doesn't actually take up any space in the ELF file, so we don't need to update the
            # OFFSET with the size of this section.
            
        else:
            if DEBUG:
                println("Section name in modifying headers: %s" % section.name)
                println("Section size: %d" % section.header['sh_size'])
            sections[i].header['sh_name'] = shstrtab.find(section.name)
            sections[i].header['sh_offset'] = 0 if section.name == '' else OFFSET
            sections[i].header['sh_addr'] = 0
            OFFSET += sections[i].header['sh_size']
            if DEBUG:
                println("%s size: %d Section Offset: %d" % (section.name, sections[i].header['sh_size'], sections[i].header['sh_offset']))
                println("OFFSET: %d" % OFFSET)  
    if DEBUG:
        println("----------------------------- Done modifying section headers --------------------------------")    
    

"""
    This function performs the first pass to gather the sections that will be modified
    and exported. Loop through each section and append it to a list of sections if
    the section name is not equal to:
        .init*
        .fini*
        .eh_frame*
        .stab*
        .debug*
        .noinit*
    These sections aren't necessary for an object file so they're ignored
    This function also grabs the symbol table, the section header string table,
    and the string table
    @param elffile: The ELFfile object
"""
def first_pass():
    global sections, NUM_SECTIONS, shstrtab, elffile
    
    # Open the program file
    # In Python getProgramFile() returns a java.io.File object :/
    # so we need to add getPath() to get the full path including the filename
    try:
        f = open(getProgramFile().getPath(), 'rb')
    except AttributeError as e:
        selectedFile = askFile("Select Executable File", "Open")
        println("Path: %s" % selectedFile)
        f = open(selectedFile.getPath(), 'rb')
    
    # Create ELF object
    elffile = ELFFile(f)
    
    # Holds the element the relocation resides in the sections list
    # If a relocation section is found (i.e. .plt* or .rel*) the 
    # RELOC_ELEM global variable will be set to the value of reloc_elem
    # Otherwise, RELOC_ELEM remains negative one which is an indicator 
    # the ELF file has no relocation section available and one must 
    # be created
    reloc_elem = 0

    
    # Get all sections in ELF file excluding those listed in this functions's description
    section_names = ''
    for sec in elffile.iter_sections():
        reloc_elem += 1
        res = [ele for ele in exclude_sections if (ele in sec.name)]
        if bool(res):
            continue
        # Build section header string table section excluding the NULL Section
        if not sec.name == '':
            shstrtab += sec.name + '\x00'
        sections.append(sec)
    # Some required sections might not be in the binary. Let's check for those and add them 
    for missing_section in required_sections:
        if missing_section not in shstrtab:
            println("We're missing a section %s! Adding it in" % missing_section)
            println("s: %s" % missing_section)
            if missing_section == '.rel.text':
                shstrtab = shstrtab.replace('.text', '.rel.text')
            else:
                # Adding missing section to the section header string table
                shstrtab += missing_section + '\x00'
            # Copying the .text section to modify it to conform to a .rel.text section
            sec = copy.deepcopy(sections[[i for i,v in enumerate(sections) if v.name == '.text'][0]])
            # Insert this section into the list of sections
            sec.name = missing_section
            sections.insert([i for i,v in enumerate(sections) if v.name == '.text'][0] + 1, sec)

    NUM_SECTIONS = len(sections) # Adding one because we're adding a relocation section
    if DEBUG:
        println("Number of sections: %d" % NUM_SECTIONS)
        print("SHSTRTAB: ", shstrtab)


"""
    This function writes the data of a section to the file.
    @param obj_file: A file descriptor representing the object file being created
    @param moduleBytes: The bytes in the module. This is retrieved in the output_obj_file
    function
    @param section: The section being written
"""
def write_section(obj_file, section):
    global section_symbols
    if DEBUG:
        println("Writing section: %s!" % section.name)
    if section.name == '.text':
        obj_file.write(moduleBytes)
    elif section.name == '.rel.text':
        # print(relocations)
        # print(sorted(relocations))
        for rel in relocations.keys():
            # Write offset
            obj_file.write(to_bytes(int(relocations[rel]['offset'], 16), 4, 'little'))
            # Write info
            obj_file.write(to_bytes(relocations[rel]['info'], 4, 'little'))
    elif section.name == '.symtab':
        # null, .text, .data, .rodata, and .bss should all have entries in the symbol table
        st_name = 0
        st_value = 0
        st_size = 0
        st_info = 0
        st_other = 0
        st_shndx = 0
        for l in section_symbols:
            if l == 'null':
                # Write the NULL symbol
                if DEBUG:
                    println("Writing the null section symbol")
                obj_file.write(to_bytes(st_name, 4, 'little'))
                obj_file.write(to_bytes(st_value, 4, 'little'))
                obj_file.write(to_bytes(st_size, 4, 'little'))
                obj_file.write(to_bytes(st_info, 1, 'little'))
                obj_file.write(to_bytes(st_other, 1, 'little'))
                obj_file.write(to_bytes(st_shndx, 2, 'little'))
            else:
                if DEBUG:
                    println("Writing the %s section symbol" % l)
                # Write the symbol for a section
                bind = ENUM_ST_INFO_BIND['STB_LOCAL']
                info_type = ENUM_ST_INFO_TYPE['STT_SECTION']
                # The calculation for st_info was taken from https://refspecs.linuxfoundation.org/elf/elf.pdf
                st_info = (((bind)<<4) + ((info_type)&0xf))
                st_shndx = [i for i,v in enumerate(sections) if v.name == l][0]
                obj_file.write(to_bytes(st_name, 4, 'little'))
                obj_file.write(to_bytes(st_value, 4, 'little'))
                obj_file.write(to_bytes(st_size, 4, 'little'))       
                obj_file.write(to_bytes(st_info, 1, 'little'))
                obj_file.write(to_bytes(st_other, 1, 'little'))
                obj_file.write(to_bytes(st_shndx, 2, 'little'))
        
        for s in symbols:
            if s == 'GLOBAL':
                st_value = 0
                for sym in symbols[s]:
                    if sym.name == '':
                        continue
                    # Write st_name
                    st_name = strtab.find(sym.name + '\x00')
                    obj_file.write(to_bytes(st_name, 4, 'little'))
                    
                    
                    if isInternalSymbol(sym):
                        st_value = write_section.offset
                        bind = ENUM_ST_INFO_BIND['STB_GLOBAL']
                        info_type = ENUM_ST_INFO_TYPE['STT_FUNC']
                        # The calculation for st_info was taken from https://refspecs.linuxfoundation.org/elf/elf.pdf
                        st_info = (((bind)<<4) + ((info_type)&0xf))
                        f = getFunctionAt(sym.getAddress())
                        body = f.getBody()
                        st_size = len(getBytes(body.getMinAddress(), body.getMaxAddress().subtract(body.getMinAddress()) + 1))
                        st_shndx = [i for i,v in enumerate(sections) if v.name == '.text'][0]
                    else:
                        bind = ENUM_ST_INFO_BIND['STB_GLOBAL']
                        info_type = ENUM_ST_INFO_TYPE['STT_NOTYPE']
                        st_info = (((bind)<<4) + ((info_type)&0xf))
                        st_name = strtab.find(sym.name + '\x00')
                        st_shndx = 0
                        st_size = 0
                        st_value = 0
                        
                    # Write st_value
                    # st_value is essentially an offset from the first symbol onward
                    if DEBUG:
                        println("Global symbol name: %s value: %d" % (sym.name, st_value))
                    obj_file.write(to_bytes(st_value, 4, 'little'))
                    write_section.offset += st_size
                    # Write st_size
                    obj_file.write(to_bytes(st_size, 4, 'little'))
                    
                    # Write st_info
                    obj_file.write(to_bytes(st_info, 1, 'little'))
                    
                    # Write st_other
                    # currently holds 0 and has no defined meaning
                    obj_file.write(to_bytes(st_other, 1, 'little'))
                    
                    # Write st_shndx
                    # Which section is this symbol defined?
                    obj_file.write(to_bytes(st_shndx, 2, 'little'))
            else:
                data_st_value = 0
                bss_st_value = 0
                for sym in symbols[s]:
                    try:
                        if sym.name == '':
                            continue
                        if DEBUG:
                            println("Local Symbol name: %s" % sym.name)
                            println("Local Symbol Address: %s" % str(sym.getAddress()))
                        bind = ENUM_ST_INFO_BIND['STB_LOCAL']
                        if bss_fragment.contains(sym.getAddress()):
                            info_type = ENUM_ST_INFO_TYPE['STT_OBJECT']
                            st_info = (((bind)<<4) + ((info_type)&0xf))
                            st_shndx = [i for i,v in enumerate(sections) if v.name == '.bss'][0]
                        else:
                            info_type = ENUM_ST_INFO_TYPE['STT_OBJECT']
                            st_info = (((bind)<<4) + ((info_type)&0xf))
                            st_shndx = [i for i,v in enumerate(sections) if v.name == '.data'][0]
                        st_name = strtab.find(sym.name + '\x00')
                        if DEBUG:  
                            println("st_name: %d" % st_name)
                            println("st_shndx: %s" % st_shndx)
                        dat = getDataAt(sym.getAddress())
                        st_size = dat.getLength()
                        #write_section.offset += st_size
                    except AttributeError as e:
                        if DEBUG:
                            println("This is not a symbol")
                        continue
                    # Write st_name
                    obj_file.write(to_bytes(st_name, 4, 'little'))
                    if bss_fragment.contains(sym.getAddress()):
                        # Write st_value            
                        obj_file.write(to_bytes(bss_st_value, 4, 'little'))
                        bss_st_value += st_size
                    else:
                        # Write st_value            
                        obj_file.write(to_bytes(data_st_value, 4, 'little'))
                        data_st_value += st_size
                    # print(sym.name, " st_value ", 0)
                    # Write st_size
                    obj_file.write(to_bytes(st_size, 4, 'little'))
                    # Write st_info
                    obj_file.write(to_bytes(st_info, 1, 'little'))
                    # Write st_other
                    # currently holds 0 and has no defined meaning
                    obj_file.write(to_bytes(st_other, 1, 'little'))
                    # Write st_shndx
                    # Which section is this symbol defined?
                    # Because this is an external symbol the section is undefined or 0
                    obj_file.write(to_bytes(st_shndx, 2, 'little'))
                    
    elif section.name == '.strtab':
        obj_file.write(strtab)
        if DEBUG:
            println("Wrote strtab section %d bytes" % len(strtab))
    elif section.name == '.shstrtab':
        obj_file.write(shstrtab)
        if DEBUG:
            println("Wrote shstrtab section %d bytes" % len(shstrtab))
    elif section.name == '.rodata':
        if DEBUG:
            println("Writing %d bytes" % len(rodata_bytes))
        obj_file.write(rodata_bytes)
    elif section.name == '.data':
        for sym in symbols['LOCAL']:
            if data_fragment.contains(sym.getAddress()):
                dat = getDataAt(sym.getAddress())
                if dat.getLength() % alignment != 0:
                    diff = (alignment - (dat.getLength() % alignment))
                    size = diff + dat.getLength()
                else:
                    size = dat.getLength()
                if DEBUG:
                    println("Symbol: %s" % sym.getName())
                    println("Symbol Address: %s" % sym.getAddress())
                    println("Data Address: %s" % dat.getAddress())
                    println("Writing %d bytes" % size)
                    println("Data Type: %s" % dat.getDataType().getDisplayName())
                    println("TESTING: %s" % dat.getValue())
                    println("Data Bytes: %s" % getBytes(dat.getAddress(), dat.getLength()))
                #obj_file.write(to_bytes(dat.getValue().getValue(), size, 'little'))
                obj_file.write(getBytes(dat.getAddress(), size))
            
    elif section.name == '.bss':
        # The .bss section doesn't actually take up any bytes in the object file so no need to write anything :)
        pass
    else:
        sec = elffile.get_section_by_name(section.name)
        obj_file.write(sec.data())
        if DEBUG:
            println("Wrote %d amount" % len(sec.data()))

"""
    This function is a wrapper that calls the other functions necessary for unlinking the object file.
    The function creates the name of the resulting unlinked object file and opens the current program executable
    so pyelftools can process it. Pyelftools is used to grab the sections in the executable so they can 
    be modified by other functions. The actual data is modified and written by other helper functions. The object
    is created by first gathering all sections we'll want to modify and export, writing the ELF header, writing the
    individual sections, and finally, writing the section headers. This is a bit different than how a compiler would 
    structure an object file, but the order does not matter so long as the linker knows where to find everything. In 
    other words, we have to make sure the offsets in the ELF and section headers are accurate. Because of this constraint,
    it was easiest to create the file in this manner because each section being written can be used by a later portion 
    being written.
    @param moduleBytes: Bytes of the module selected by the user
"""
def unlink_object_file():

       
    # The resulting object file
    # TODO: Update to use Ghidra API to get filename
    # fname = moduleName + '_unlinked.o'
    # path = currentProgram.getExecutablePath()
    # fname = path[:path.rindex('/')+1] + fname
    fname = output_arg + '/' + moduleName + '_unlinked.o'
    println("File name: %s" % fname)
    # fname = fname.getPath()
    obj_file = open(fname, 'wb')
    
    # Modify the section headers
    modify_section_headers()
    # The section headers have been modified, let's write the ELF headers to a file
    write_elf_header(obj_file)
    # Let's now write the section
    for sec in sections:
        write_section(obj_file, sec)
    # Finally let's write the section headers
    for sec in sections:
        write_section_headers(obj_file, sec)
    
    # The unlinked object file is now complete, close the file
    obj_file.close()

"""
    This function updates the module bytes at the given offset with the specific bytes
    
"""
def update_module_bytes(offset, newBytes):
    global moduleBytes
    moduleBytes[offset:offset+4] = newBytes

"""
  This function grabs the text section for the module by getting the bytes between boundary1 and boundary2
"""
def get_module_bytes():
    
    global moduleBytes
    
    try:
        # Added one at the end because a byte was being cut off if I just subtracted maxModuleAddress from minModuleAddress
        # Would like to try and find a more elegant way but this works for now
        moduleBytes = getBytes(minModuleAddress, (maxModuleAddress.subtract(minModuleAddress) + 1))
                
    except MemoryAccessException:
    # TODO Auto-generated catch block
        println("Problem getting bytes within module... ")
        e.printStackTrace()

"""
 This function places all of the relocations in a relocation dictionary. Additionally, it modifies
 the original bytes such that they are consistent with what a normal compiler would do. For example,
 for external function calls, the compiler places the following bytes at the address where the
 external function was called: FF FF FE EB, where EB is the call instruction and the other three bytes
 are dummy values. The string table consists of all the symbol names (i.e. function/variable names). 
 This "table" is constructed here and later used for writing the strtab section.
"""      
def get_relocations():
    global relocations, NUM_RELOCS, sections, strtab, moduleBytes, total_symbols, rodata_bytes
    bss_offset = 0
    data_offset = 0
    rodata_offset = 0
    last_local_symbol = 0
    newBytes = b'\xff\xff\xfe\xeb'
    
    boundary1, boundary2 = minModuleAddress, maxModuleAddress

    
    # This attempts to gather most relocations.
    # Iterate through the dictionary of symbols
    for key, lst in symbols.items():
        # Iterate through each symbol
        for sym in lst:
            if DEBUG:
                println("-----------------------------------")
            if not rodata_fragment.contains(sym.getAddress()):
                strtab.append(sym.getName())
                if DEBUG:
                    println("Not a rodata symbol Symbol Name: %s" % sym.getName())
                symbol_type = sym.getSymbolType().toString()

                # Does this symbol have any references
                if sym.hasReferences() or sym.hasMultipleReferences():
                    symRef = sym.getReferences()
                    if DEBUG:
                        println("Symbol has references...")
                    # Iterate through each symbols references
                    
                    for ref in symRef:
                        # println("Reference address: %s" % ref.getFromAddress())
                        if ref.getFromAddress().toString() == 'Entry Point':
                            continue
                        # Is the reference within the boundary? If so, a relocation should occur
                        if isInternalSymbol(ref):
                            if DEBUG:
                                println("Reference is within module boundary")
                            # Here, the offset is the offset the relocation should occur
                            # That is, the address where the symbol is referenced minus 
                            # the lower bound of the module
                            offset = ref.getFromAddress().subtract(boundary1)
                        
                            # key for relocation will be relocation<NUM>
                            key = "relocation" + str(NUM_RELOCS)
                        
                        
                            # Create the info field in the relocation by appending a number
                            # and a hexadecimal representation of the R_ARM_CALL enumerated data type
                            # The info field in the relocation table is composed of the index into 
                            # the symbol table followed by the type of relocation (i.e. R_ARM_CALL)
                            # The [2:] is necessary so we only grab the numbers and omit the '0x'
                            # TODO: modify this so that it checks what type of symbol this is
                            # The type of symbol will change the info field since this will be a 
                            # different type of relocation
                            func_call = ENUM_RELOC_TYPE_ARM['R_ARM_CALL']
                            data_reloc = ENUM_RELOC_TYPE_ARM['R_ARM_ABS32']
                            if symbol_type == 'Function':
                                if DEBUG:
                                    println("Symbol is a function")
                                NUM_RELOCS += 1
                                if len(relocations.values()) >= 1:
                                    # If the symbol already exists set the info field to match the other relocation 
                                    # entry for the same symbol 
                                    for d in relocations.values():
                                        if d['name'] == sym.getName():
                                            info = d['info']
                                        else:
                                            reloc_type = func_call
                                            t = hex(reloc_type)
                                            reloc_type = t[2:] if len(t) == 4 else '0' + hex(reloc_type)[2:]
                                            info = hex(total_symbols)[2:] + reloc_type
                                            info = int(info, 16) # Change into an integer so we can call to_bytes on it later
                                else:
                                    reloc_type = func_call
                                    t = hex(reloc_type)
                                    reloc_type = t[2:] if len(t) == 4 else '0' + hex(reloc_type)[2:]
                                    info = hex(total_symbols)[2:] + reloc_type
                                    info = int(info, 16) # Change into an integer so we can call to_bytes on it later
                                    
                            else:
                                # The symbol is not a function
                                if DEBUG:
                                    println("Symbol is not a function")
                                if ref.getReferenceType().toString() != 'DATA':
                                    continue
                                NUM_RELOCS += 1
                                dat = getDataAt(sym.getAddress())
                                if DEBUG:
                                    println("Symbol: %s Address: %s" % (sym.getName(), sym.getAddress()))
                                    println("Value: %s Length: %s" % (dat.getValue(), dat.getLength()))
                                if len(relocations.values()) >= 1:
                                    # If the symbol already exists set the info field to match the other relocation 
                                    # entry for the same symbol 
                                    for d in relocations.values():
                                        if d['name'] == sym.getName():
                                            info = d['info']
                                        else:
                                            reloc_type = data_reloc
                                            t = hex(reloc_type)
                                            reloc_type = t[2:] if len(t) == 4 else '0' + hex(reloc_type)[2:]
                                            if bss_fragment.contains(sym.getAddress()):
                                                info = str(4)
                                            else:
                                                info = str(3)
                                            info += reloc_type
                                            if DEBUG:
                                                println("Info bss or data: %s" % info)
                                            info = int(info, 16) # Change into an integer so we can call to_bytes on it later
                                else:
                                    reloc_type = data_reloc
                                    t = hex(reloc_type)
                                    reloc_type = t[2:] if len(t) == 4 else '0' + hex(reloc_type)[2:]
                                    if bss_fragment.contains(sym.getAddress()):
                                        info = str(4)
                                    else:
                                        info = str(3)
                                    info += reloc_type
                                    if DEBUG:
                                        println("Info bss or data: %s" % info)
                                    info = int(info, 16) # Change into an integer so we can call to_bytes on it later
                            relocations[key] = {'name': sym.getName(), 'offset': hex(offset).lstrip("0x").rstrip("L"), 'addr': ref.getFromAddress(), 'info': info}
                            # Modify the bytes at the offset with the bytes \xfe\xff\xff\xeb
                            if symbol_type == 'Function':
                                #moduleBytes[offset:offset+4] = newBytes
                                update_module_bytes(offset, newBytes)
                            else:
                                if bss_fragment.contains(sym.getAddress()):
                                    #moduleBytes[offset:offset+4] = to_bytes(bss_offset, 4, 'little')
                                    update_module_bytes(offset, to_bytes(bss_offset, 4, 'little'))
                                    bss_offset += 4
                                else:
                                    #moduleBytes[offset:offset+4] = to_bytes(data_offset, 4, 'little')
                                    update_module_bytes(offset, to_bytes(data_offset, 4, 'little'))
                                    data_offset += 4
                    total_symbols += 1
            # Probably not best to handle this as an exception but this is the case where we have to perform 
            # a relocation on the rodata section. These aren't symbols like the other elements in the symbols 
            # dictionary so we have to treat them a little differently
            else:
                if DEBUG:
                    println("This is in the rodata section")
                refs = sym.getReferenceIteratorTo()
                for ref in refs:
                    # if ref.getFromAddress().compareTo(minModuleAddress) >= 0 and \
                    # ref.getFromAddress().compareTo(maxModuleAddress) <= 0:
                    if isInternalSymbol(ref):
                        if ref.getReferenceType().toString() != 'DATA':
                            continue
                        # This is a string that's too small to be recognized by Ghidra and the 
                        # analyst didn't manually type it as a string
                        short_str = False
                        if 'undefined' in sym.getDataType().getDisplayName():
                            short_str = True
                            str_array = bytearray()
                            str_array.append(getByte(sym.getAddress()))
                            n = sym.getAddress().next()
                            while getByte(n) != 0:
                                str_array.append(getByte(n))
                                n = n.next()
                            if DEBUG:
                                println("str_array: %s" % str_array)
                            rodata_bytes += str_array
                        

                        offset = ref.getFromAddress().subtract(boundary1)

                        # The original bytes written here is the offset into the rodata section
                        # The offset is updated later on
                        update_module_bytes(offset, to_bytes(rodata_offset, 4, 'little'))
                        info = str(2) # Would like to get away from hard coding this
                        reloc_type = data_reloc
                        t = hex(reloc_type)
                        reloc_type = t[2:] if len(t) == 4 else '0' + hex(reloc_type)[2:]
                        info += reloc_type
                        info = int(info, 16)

                        
                        if short_str:
                            key = "relocation" + str(NUM_RELOCS)
                            NUM_RELOCS += 1
                            relocations[key] = {'name': str_array, 'offset': hex(offset).lstrip("0x").rstrip("L"), 'addr': ref.getFromAddress(), 'info': info}
                            rodata_offset += len(str_array)
                        else:
                            
                            # Using getBytes will allow us to get all the bytes from the start address to the end
                            # We add one to the length to include the null byte at the end of the byte array. We 
                            # add 1 yet again because after each entry in the rodata section, there's a null byte 
                            # dividing each entry in the rodata section. So the offset will be the length of the
                            # current string plus that extra null byte and that's where the next
                            if isinstance(sym.getValue(), unicode) or isinstance(sym.getValue(), str):
                                key = "relocation" + str(NUM_RELOCS)
                                NUM_RELOCS += 1
                                relocations[key] = {'name': sym.getValue(), 'offset': hex(offset).lstrip("0x").rstrip("L"), 'addr': ref.getFromAddress(), 'info': info}
                                newString = getBytes(sym.getAddress(), len(sym.getValue()) + 1)
                                if DEBUG:
                                    println("newString Data: %s" % newString)
                                    println("newString length BEFORE: %d" % len(newString))
                                
                                if len(newString) % alignment != 0:
                                    if DEBUG:
                                        println("This string is not 4 byte aligned. Need to add some bytes")
                                    diff = len(newString) % alignment
                                    padding = alignment - diff
                                    pad = to_bytes(0, padding, 'little')
                                    if DEBUG:
                                        println("Length of pad: %d" % len(pad))
                                        println("Pad bytes: %s" % pad)
                                        println("Type of element: %s" % type(newString[0]))
                                        println("element: %s" % newString[0])
                                    for s in pad:
                                        newString.append(ord(s))
                                    
                                    # newString.append(to_bytes(0, padding, 'little'))
                                    # rodata_bytes += to_bytes(0, padding, 'little')
                                if DEBUG:
                                    println("newString length AFTER: %d" % len(newString))
                                    println("newString: %s" % newString)
                                rodata_bytes += (newString)
                                if DEBUG:
                                    println("rodata_bytes: %s" % rodata_bytes)
                                rodata_offset += len(newString)
                            else:
                                if DEBUG:
                                    println("Address: %s" % sym.getAddress())
                                    println("Value: %s" % sym.getValue())
                                # rodata_offset += 4
                                # rodata_bytes += to_bytes(0, 4, 'little')
                        # println("Rodata offset: %s" % hex(rodata_offset))
            if DEBUG:
                println("-----------------------------------")
    if DEBUG:
        println("----------------------------------------------------------------------------------------------------------------------")
        print(relocations)
        # println("Total Symbols: %d " % total_symbols)
        println("----------------------------------------------------------------------------------------------------------------------")
        
    strtab = '\x00' + '\x00'.join(strtab) + '\x00'
    if DEBUG:
        print("Strtab: " , strtab)
    

# get script args
args = getScriptArgs()
module_arg = args[0] if len(args) > 0 else ""
output_arg = args[1] if len(args) > 1 else os.path.dirname(parseFile(getSourceFile().getCanonicalPath()).getPath())

print("ELF Output: %s %s" % (module_arg, output_arg))

# executable_arg = args[2] if len(args) > 2 else    
write_section.offset = 0
if SelectModule(module_arg):
    
    # Perform first pass of ELF file to gather all the sections we'll modify and export. 
    first_pass()
    get_symbols()
    get_module_bytes()
    get_relocations()
    unlink_object_file()
