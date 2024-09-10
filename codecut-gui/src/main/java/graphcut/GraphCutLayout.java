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
 * Borrows heavily from Ghidra File /Features Graph FunctionCalls/src/main/java/functioncalls/graph/layout/BowTieLayout.java
 */


package graphcut;

import java.awt.Rectangle;
import java.awt.geom.Point2D;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import ghidra.graph.VisualGraph;
import ghidra.graph.viewer.layout.AbstractVisualGraphLayout;
import ghidra.graph.viewer.layout.Column;
import ghidra.graph.viewer.layout.GridLocationMap;
import ghidra.graph.viewer.layout.LayoutPositions;
import ghidra.graph.viewer.layout.Row;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class GraphCutLayout extends AbstractVisualGraphLayout<GraphCutVertex, GraphCutEdge> {
	
	protected GraphCutLayout(GraphCutGraph graph, String name){
		super(graph, name);
	}
	
	public AbstractVisualGraphLayout<GraphCutVertex, GraphCutEdge> createClonedLayout(VisualGraph<GraphCutVertex, GraphCutEdge> newGraph){
		if (!(newGraph instanceof GraphCutGraph)) {
			throw new IllegalArgumentException("Must pass a GraphCut Graph to clone");
		}
		
		GraphCutLayout newLayout = new GraphCutLayout((GraphCutGraph) newGraph, getLayoutName());
		return newLayout;
	}
	
	@Override
	protected Point2D getVertexLocation(GraphCutVertex v, Column col, Row<GraphCutVertex> row, Rectangle bounds) {
		return getCenteredVertexLocation(v, col, row, bounds);
	}
	
	@Override 
	public boolean isCondensedLayout() {
		return false;
	}
	
	@Override
	public GraphCutGraph getVisualGraph() {
		return (GraphCutGraph) getGraph();
	}
	
	@Override
	protected GridLocationMap<GraphCutVertex, GraphCutEdge> performInitialGridLayout(VisualGraph<GraphCutVertex,GraphCutEdge> g) throws CancelledException {
		if (!(g instanceof GraphCutGraph)) {
			throw new IllegalArgumentException("This layout can only be used with the GraphCutGraph");
		}
		
		return layoutGraphCutGraph((GraphCutGraph)g);
	}
	
	@Override
	public LayoutPositions<GraphCutVertex, GraphCutEdge> calculateLocations(VisualGraph<GraphCutVertex, GraphCutEdge> g, TaskMonitor taskMonitor){
		LayoutPositions<GraphCutVertex, GraphCutEdge> locs = super.calculateLocations(g, taskMonitor);
		return locs;
	}
	
	private GridLocationMap<GraphCutVertex, GraphCutEdge> layoutGraphCutGraph(GraphCutGraph g){
		GridLocationMap<GraphCutVertex, GraphCutEdge> grid = new GridLocationMap<>();
		
		GraphCutVertex source = Objects.requireNonNull(g.getSource());
		// Incoming nodes on top
		// Sorted by id
		
		List<GraphCutEdge> inEdges = new ArrayList<>(g.getInEdges(source));
		List<GraphCutVertex> inVertices = inEdges.stream().map(e -> e.getStart()).collect(Collectors.toList());
		inVertices.sort((v1,v2) -> v1.getID() > v2.getID() ? +1 : v1.getID() < v2.getID() ? -1 : 0);
		
		//first row -> incoming nodes
		int row = 0;
		for(int col = 0; col < inVertices.size(); col++) {
			GraphCutVertex v = inVertices.get(col);
			grid.set(v, row, col);
		}
		
		//middle row -> source
		row = 1;
		grid.set(source, row, 0);
		
		//bottom row -> outgoing nodes
		List<GraphCutEdge> outEdges = new ArrayList<>(g.getOutEdges(source));
		List<GraphCutVertex> outVertices = outEdges.stream().map(e -> e.getEnd()).collect(Collectors.toList());
		
		outVertices.removeAll(inVertices); //prevent cycles
		outVertices.sort((v1,v2) -> v1.getID() > v2.getID() ? +1 : v1.getID() < v2.getID() ? -1 : 0);
		row = 2;
		for (int col = 0; col < outVertices.size(); col++) {
			GraphCutVertex v = outVertices.get(col);
			grid.set(v, row, col);
		}
		
		grid.centerRows();
		return grid;
		
	}

}
