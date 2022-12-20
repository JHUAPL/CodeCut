/* ###
* © 2022 The Johns Hopkins University Applied Physics Laboratory LLC
* (JHU/APL).
*
* NO WARRANTY, NO LIABILITY. THIS MATERIAL IS PROVIDED “AS IS.” JHU/APL
* MAKES NO REPRESENTATION OR WARRANTY WITH RESPECT TO THE PERFORMANCE OF
* THE MATERIALS, INCLUDING THEIR SAFETY, EFFECTIVENESS, OR COMMERCIAL
* VIABILITY, AND DISCLAIMS ALL WARRANTIES IN THE MATERIAL, WHETHER
* EXPRESS OR IMPLIED, INCLUDING (BUT NOT LIMITED TO) ANY AND ALL IMPLIED
* WARRANTIES OF PERFORMANCE, MERCHANTABILITY, FITNESS FOR A PARTICULAR
* PURPOSE, AND NON-INFRINGEMENT OF INTELLECTUAL PROPERTY OR OTHER THIRD
* PARTY RIGHTS. ANY USER OF THE MATERIAL ASSUMES THE ENTIRE RISK AND
* LIABILITY FOR USING THE MATERIAL. IN NO EVENT SHALL JHU/APL BE LIABLE
* TO ANY USER OF THE MATERIAL FOR ANY ACTUAL, INDIRECT, CONSEQUENTIAL,
* SPECIAL OR OTHER DAMAGES ARISING FROM THE USE OF, OR INABILITY TO USE,
* THE MATERIAL, INCLUDING, BUT NOT LIMITED TO, ANY DAMAGES FOR LOST
* PROFITS.
*
* This material is based upon work supported by the Defense Advanced Research
* Projects Agency (DARPA) and Naval Information Warfare Center Pacific (NIWC Pacific)
* under Contract Number N66001-20-C-4024.
*
* HAVE A NICE DAY.
*/

package codecutguiv2;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.util.ProgramLocation;
import ghidra.util.task.TaskMonitor;

class SymbolPlaceholder implements Symbol{

	private long id; 
	private Address addr; 
	private Program prog; 
	
	SymbolPlaceholder(long id, Address addr, Program p){ 
		this.id = id; 
		this.addr = addr; 
		this.prog = p; 
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof Symbol)) {
			return false;
		}
		if (obj == this) {
			return true;
		}

		// this class is only ever equal if the id matches
		Symbol s = (Symbol) obj;
		if (getID() == s.getID()) {
			return true;
		}
		return false;
	}
	@Override
	public int hashCode() {
		return (int) id;
	}

	@Override
	public long getID() {
		return id;
	}

	@Override
	public Address getAddress() {
		return addr;
	}

	@Override
	public SymbolType getSymbolType() {
		throw new UnsupportedOperationException();
	}

	@Override
	public ProgramLocation getProgramLocation() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isExternal() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Object getObject() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isPrimary() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isValidParent(Namespace parent) {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getName() {
		return null; 
	}

	@Override
	public String[] getPath() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Program getProgram() {
		throw new UnsupportedOperationException(); 
	}

	@Override
	public String getName(boolean includeNamespace) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Namespace getParentNamespace() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Symbol getParentSymbol() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isDescendant(Namespace namespace) {
		throw new UnsupportedOperationException();
	}

	@Override
	public int getReferenceCount() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean hasMultipleReferences() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean hasReferences() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Reference[] getReferences(TaskMonitor monitor) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Reference[] getReferences() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setName(String newName, SourceType source) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setNamespace(Namespace newNamespace) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setNameAndNamespace(String newName, Namespace newNamespace, SourceType source) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean delete() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isPinned() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setPinned(boolean pinned) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isDynamic() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean setPrimary() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isExternalEntryPoint() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isGlobal() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setSource(SourceType source) {
		throw new UnsupportedOperationException();
	}

	@Override
	public SourceType getSource() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isDeleted() {
		throw new UnsupportedOperationException();
	}

	@Override
	public String toString() {
		return getClass().getSimpleName() + "[id=" + id + ", address=" + addr + "]";
	}
}
