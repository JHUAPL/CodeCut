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
 * Borrows from Ghidra file /Features Graph FunctionCalls/src/main/java/functioncalls/plugin/FcgData.java
 */


package graphcut;

import ghidra.graph.viewer.GraphPerspectiveInfo;
import ghidra.program.model.symbol.Namespace;

/**
 * Allows us to retrieve and work on the graph. Makes caching data simple
 */
public interface GraphCutData {
	
	/**
	 * The namespace of this data
	 * @return the namespace
	 */
	Namespace getNamespace();
	
	/**
	 * The graph of this data
	 * @return the graph
	 */
	GraphCutGraph getGraph();
	
	/**
	 * Returns the cache of edges. Not in the graph but used to track existing edges that are not yet in the graph.
	 * @return
	 */
	NamespaceEdgeCache getNamespaceEdgeCache();
	
	/**
	 * True if this data has a valid namespace
	 * @return true if this data has a valid namespace
	 */
	boolean hasResults();
	
	/**
	 * False if the graph in this data has not yet been loaded
	 */
	boolean isInitialized();
	
	/**
	 * Dispose the contents of this data
	 */
	void dispose();
	
	/**
	 * Returns the view's graph perspective. this is used by the view to restore itself.
	 * @return the view's graph perspective
	 */
	GraphPerspectiveInfo<GraphCutVertex, GraphCutEdge> getGraphPerspective();
	
	/**
	 * Set the view information for this graph data
	 * @param info the perspective to set
	 */
	void setGraphPerspective(GraphPerspectiveInfo<GraphCutVertex, GraphCutEdge> info);
	
	/**
	 * Returns true if this data's namespace is equal to the given one
	 * @param ns the namespace to test
	 * @return true if this data's namespace is equal to the given one
	 */
	boolean isNamespace(Namespace ns);
}
