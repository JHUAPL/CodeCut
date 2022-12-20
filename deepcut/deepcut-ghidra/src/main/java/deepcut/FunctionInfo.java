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

package deepcut;

import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

class FunctionInfo {
    private Function function;

    private Address address;
    private long addressIndex;

    private String name;

    // `true` if the function is either external or a thunk function.
    private boolean isExternalThunk;

    private List<EdgeInfo> incomingEdges;
    private List<EdgeInfo> outgoingEdges;

    // `true` if the function ever calls itself
    private boolean isRecursive;

    public FunctionInfo(Function function) {
        this.function = function;
        address = function.getEntryPoint();
        name = function.getName();

        // will be set in a later pass
        addressIndex = -1;
        isRecursive = false;

        isExternalThunk = function.isThunk() || function.isExternal() ||
			(!function.getParentNamespace().isGlobal());

        incomingEdges = new ArrayList<EdgeInfo>();
        outgoingEdges = new ArrayList<EdgeInfo>();
    }

	public void addIncomingEdge(EdgeInfo edge) {
		incomingEdges.add(edge);
	}

	public List<EdgeInfo> getIncomingEdges() {
		return incomingEdges;
	}

	public int getIncomingEdgeSize() {
		return incomingEdges.size();
	}
	
	public void addOutgoingEdge(EdgeInfo edge) {
		outgoingEdges.add(edge);
	}
	
	public List<EdgeInfo> getOutgoingEdges() {
		return outgoingEdges;
	}
	
	public int getOutgoingEdgeSize() {
		return outgoingEdges.size();
	}
	
	public Function getFunction() {
        return function;
    }

	public void setIsRecursive(boolean val) {
		isRecursive = val;
	}
	
    public boolean getIsRecursive() {
		return isRecursive;
	}

	public void setAddress(Address address) {
		this.address = address;
	}
	
    public Address getAddress() {
        return address;
    }

    public void setAddressIndex(int index) {
		this.addressIndex = index;
	}
	
    public long getAddressIndex() {
		return addressIndex;
	}

	public String getName() {
		return name;
	}
	
    @Override
    public String toString() {
        return getFunction().getName() + " " + address +
			" (" + addressIndex + ")";
    }

}
