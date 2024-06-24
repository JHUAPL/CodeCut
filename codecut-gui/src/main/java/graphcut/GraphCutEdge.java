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

package graphcut;

import ghidra.graph.viewer.edge.AbstractVisualEdge;
import graphcut.GraphCutVertex;
/**
 * A GraphCut Edge
 */

public class GraphCutEdge extends AbstractVisualEdge<GraphCutVertex> {
	
	public GraphCutEdge(GraphCutVertex start, GraphCutVertex end) {
		super(start, end);
	}
	
	@SuppressWarnings("unchecked")
	
	@Override
	public GraphCutEdge cloneEdge(GraphCutVertex start, GraphCutVertex end) {
		return new GraphCutEdge(start, end);
	}
	
	/**
	 * Returns true if an edge is direct from a lower level.
	 * @return true if this edge is a direct edge
	 */
	public boolean isDirectEdge() {
		GraphCutLevel startLevel = getStart().getLevel();
		GraphCutLevel endLevel = getEnd().getLevel();
		if(startLevel.isSource() || endLevel.isSource()) {
			return true;
		}
		
		GraphCutLevel parent = startLevel.parent();
		if (parent.equals(endLevel)) {
			return true;
		}
		
		GraphCutLevel child = startLevel.child();
		return child.equals(endLevel);
	}
}
