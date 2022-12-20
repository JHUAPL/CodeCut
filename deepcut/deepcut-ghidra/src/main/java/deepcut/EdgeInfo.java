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

class EdgeInfo {
    private FunctionInfo src;
    private FunctionInfo dst;

    private int multiplicity;

    /*
     distance between the two functions,
        either in terms of address
        or number of functions in between.
     */
    private double addressDistance;
    private double indexDistance;

    private boolean isSelfCall;

    public EdgeInfo(FunctionInfo src, FunctionInfo dst, int multiplicity) {
        this.src = src;
        this.dst = dst;

        this.multiplicity = multiplicity;

        this.addressDistance = (double) dst.getAddress().subtract(src.getAddress());
        this.indexDistance = (double) dst.getAddressIndex() - src.getAddressIndex();
    }

	public FunctionInfo getSrc() {
		return src;
	}
	
	public FunctionInfo getDst() {
		return dst;
	}

	public int getMultiplicity() {
		return multiplicity;
	}

	public double getAddressDistance() {
		return addressDistance;
	}

	public double getIndexDistance() {
		return indexDistance;
	}

	public boolean getisSelfCall() {
		return isSelfCall;
	}

	public long getSrcAddressIndex() {
		return src.getAddressIndex();
	}

	public long getDstAddressIndex() {
		return dst.getAddressIndex();
	}

    @Override
    public String toString() {
        return String.format("%-20s -> %20-s\t#%d", src.getName(),
							 dst.getName(), multiplicity);
    }
}
