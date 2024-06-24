/* ###
 * © 2021 The Johns Hopkins University Applied Physics Laboratory LLC (JHU/APL).  
 * All Rights Reserved.
 * 
 * This material may be only be used, modified, or reproduced by or for the U.S. 
 * Government pursuant to the license rights granted under the clauses at 
 * DFARS 252.227-7013/7014 or FAR 52.227-14. For any other permission, please 
 * contact the Office of Technology Transfer at JHU/APL.
 * 
 * NO WARRANTY, NO LIABILITY. THIS MATERIAL IS PROVIDED “AS IS.” JHU/APL MAKES 
 * NO REPRESENTATION OR WARRANTY WITH RESPECT TO THE PERFORMANCE OF THE MATERIALS, 
 * INCLUDING THEIR SAFETY, EFFECTIVENESS, OR COMMERCIAL VIABILITY, AND DISCLAIMS 
 * ALL WARRANTIES IN THE MATERIAL, WHETHER EXPRESS OR IMPLIED, INCLUDING 
 * (BUT NOT LIMITED TO) ANY AND ALL IMPLIED WARRANTIES OF PERFORMANCE, 
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT OF 
 * INTELLECTUAL PROPERTY OR OTHER THIRD PARTY RIGHTS. ANY USER OF THE MATERIAL 
 * ASSUMES THE ENTIRE RISK AND LIABILITY FOR USING THE MATERIAL. IN NO EVENT SHALL 
 * JHU/APL BE LIABLE TO ANY USER OF THE MATERIAL FOR ANY ACTUAL, INDIRECT, 
 * CONSEQUENTIAL, SPECIAL OR OTHER DAMAGES ARISING FROM THE USE OF, OR INABILITY TO 
 * USE, THE MATERIAL, INCLUDING, BUT NOT LIMITED TO, ANY DAMAGES FOR LOST PROFITS. 
 *
 * HAVE A NICE DAY.
 */

/* This material is based upon work supported by the Defense Advanced Research
 * Projects Agency (DARPA) and Naval Information Warfare Center Pacific (NIWC Pacific)
 * under Contract Number N66001-20-C-4024.
*/

/*
 * Heavily Borrowed from Ghidra file /Features Graph FunctionCalls/src/main/java/functioncalls/graph/FcgEdge.java
 */


package graphcut;

import static functioncalls.graph.FcgDirection.*;

import functioncalls.graph.FcgDirection;


// A container class that represents a GraphCut row.

public class GraphCutLevel implements Comparable<GraphCutLevel> {

	private int row;
	private FcgDirection direction;
	
	public static GraphCutLevel sourceLevel() {
		return new GraphCutLevel(0, IN_AND_OUT);
	}
	
	public GraphCutLevel(int distance, FcgDirection direction) {
		this.row = toRow(distance);
		this.direction = direction;
		
		if (row == 0) {
			throw new IllegalArgumentException("Graph Cut uses a 1-based row system");
		}
		
		if (row == 1 && direction != IN_AND_OUT) {
			throw new IllegalArgumentException("Row 1 must be FcgDirection.IN_AND_OUT");
		}
	}
	
	private int toRow(int distance) {
		int oneBased = distance + 1;
		return (direction == OUT) ? -oneBased : oneBased;
	}
	
	public int getRow() {
		return row;
	}
	
	public int getDistance() {
		return Math.abs(row) - 1;
	}
	
	public FcgDirection getDirection() {
		return direction;
	}
	
	/**
	 * Returns true if this level is level 1
	 * @return true if this level represents the source level
	 */
	public boolean isSource() {
		return direction.isSource();
	}
	
	public GraphCutLevel parent() {
		if (direction == IN_AND_OUT) {
			// undefined--we are the parent of all
			throw new IllegalArgumentException(
				"To get the parent of the source level you must use the constructor directly");
		}

		int newDistance = getDistance() - 1;
		FcgDirection newDirection = direction;
		if (newDistance == 0) {
			newDirection = IN_AND_OUT;
		}
		return new GraphCutLevel(newDistance, newDirection);
	}
	
	public GraphCutLevel child() {
		if (direction == IN_AND_OUT) {
			// undefined--this node goes in both directions
			throw new IllegalArgumentException(
				"To get the child of the source level you " + "must use the constructor directly");
		}

		return child(direction);
	}
	
	public boolean isParentOf(GraphCutLevel other) {
		if (isSource()) {
			return other.getDistance() == 1;
		}

		if (direction != other.direction) {
			return false;
		}

		// e.g., row 2 - row 1 = 1
		return other.getDistance() - getDistance() == 1;
	}
	
	public boolean isChildOf(GraphCutLevel other) {
		return other.isParentOf(this);
	}
	
	public GraphCutLevel child(FcgDirection newDirection) {
		if (newDirection == IN_AND_OUT) {
			// undefined--IN_AND_OUT goes in both directions
			throw new IllegalArgumentException("Direction cannot be IN_AND_OUT");
		}

		int newDistance = getDistance() + 1;
		return new GraphCutLevel(newDistance, newDirection);
	}

	@Override
	public String toString() {
		return direction + " - row " + Integer.toString(getRelativeRow());
	}
	
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((direction == null) ? 0 : direction.hashCode());
		result = prime * result + row;
		return result;
	}
	
	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}

		GraphCutLevel other = (GraphCutLevel) obj;
		if (direction != other.direction) {
			return false;
		}
		if (row != other.row) {
			return false;
		}
		return true;
	}
	
	private int getRelativeRow() {
		return direction == OUT ? -row : row;
	}
	
	@Override
	public int compareTo(GraphCutLevel l2) {
		
		int result = getDirection().compareTo(l2.getDirection());
		if (result != 0) {
			return result;
		}
		
		return -(getRelativeRow() - l2.getRelativeRow());
	}
}
