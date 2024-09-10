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
 * Borrows from Ghidra file /Features Graph FunctionCalls/src/main/java/functioncalls/graph/layout/BowTieLayoutProvider.java
 */

package graphcut;

import javax.swing.Icon;

import generic.theme.GIcon;
import ghidra.graph.viewer.layout.AbstractLayoutProvider;
import ghidra.graph.viewer.layout.VisualGraphLayout;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A layout provider for GraphCut
 */
public class GraphCutLayoutProvider extends AbstractLayoutProvider<GraphCutVertex, GraphCutEdge, GraphCutGraph> {
	public static final String NAME = "GraphCut Layout";
	private static final Icon DEFAULT_ICON = new GIcon("icon.plugin.fcg.layout.bow.tie");
	
	@Override
	public VisualGraphLayout<GraphCutVertex, GraphCutEdge> getLayout(GraphCutGraph graph, TaskMonitor taskMonitor) throws CancelledException{
		
		GraphCutLayout layout = new GraphCutLayout(graph, NAME);
		initVertexLocations(graph, layout);
		return layout;
	}
	
	@Override
	public String getLayoutName() {
		return NAME;
	}
	
	@Override
	public Icon getActionIcon() {
		return DEFAULT_ICON;
	}
}
