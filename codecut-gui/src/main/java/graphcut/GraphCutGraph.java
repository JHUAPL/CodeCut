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
 * Heavily Borrows from Ghidra file /Features Graph FunctionCalls/src/main/java/functioncalls/graph/FunctionCallGraph.java
 */


package graphcut;

import java.util.*;

import org.apache.commons.collections4.IterableUtils;
import org.apache.commons.collections4.map.LazyMap;

import functioncalls.graph.FcgDirection;
import ghidra.graph.graphs.FilteringVisualGraph;
import ghidra.graph.viewer.layout.VisualGraphLayout;
import ghidra.program.model.symbol.Namespace;


/*
 * A graph for the GraphCut Plugin
 */
public class GraphCutGraph extends FilteringVisualGraph<GraphCutVertex, GraphCutEdge> {
	
	private VisualGraphLayout<GraphCutVertex, GraphCutEdge> layout;
	private GraphCutVertex source;
	private Map<Namespace, GraphCutVertex> verticesByNamespace = new HashMap<>();
	private Comparator<GraphCutVertex> vertexComparator = 
			(v1,v2) -> v1.getID() > v2.getID() ? +1 : v1.getID() < v2.getID() ? -1 : 0;
	private Map<GraphCutLevel, Set<GraphCutVertex>> verticesByLevel = 
			LazyMap.lazyMap(new HashMap<>(), () -> new TreeSet<>(vertexComparator));
	
	/**
	 * Sets the source vertex from which the graph originates
	 * @param the source vertex
	 */
	public void setSource(GraphCutVertex source) {
		if (this.source != null) {
			throw new IllegalStateException("Cannot change graph source once it has been created");
		}
		
		this.source = source;
		addVertex(source);
	}
	
	/**
	 * Returns the vertex from which the graph is created
	 * @return source vertex
	 */
	public GraphCutVertex getSource() {
		return source;
	}
	
	/**
	 * returns whether there is a vertex for the given namespace
	 * @param ns Namespace
	 * @return True if graph contains a vertex for the namespace
	 */
	public boolean containsNamespace(Namespace ns) {
		return verticesByNamespace.containsKey(ns);
	}
	
	/**
	 * Returns the vertex for the given namespace
	 * @param ns Namespace
	 * @return the vertex for the given namespace
	 */
	public GraphCutVertex getVertex(Namespace ns) {
		return verticesByNamespace.get(ns);
	}
	
	
	/**
	 * Return all vertices in the given level
	 * @param level the level to retrieve
	 * @return all vertices in the given level
	 */
	public Iterable<GraphCutVertex> getVerticesByLevel(GraphCutLevel level){
		return IterableUtils.unmodifiableIterable(verticesByLevel.get(level));
	}
	
	/**
	 * Returns the level furthest from the source node in the given direction
	 * @param direction the direction to search
	 * @return the furthest level
	 */
	public GraphCutLevel getLargestLevel(FcgDirection direction) {
		GraphCutLevel greatest = new GraphCutLevel(1, direction);
		
		Set<GraphCutLevel> keys = verticesByLevel.keySet();
		for (GraphCutLevel level : keys) {
			if (level.getDirection() != direction) {
				continue;
			}
			
			if (level.getRow() > greatest.getRow()) {
				greatest = level;
			}
		}
		return greatest;
	}
	
	@Override
	public VisualGraphLayout<GraphCutVertex, GraphCutEdge> getLayout(){
		return layout;
	}
	
	@Override
	public GraphCutGraph copy() {
		
		GraphCutGraph newGraph = new GraphCutGraph();
		for (GraphCutVertex v : vertices.keySet()) {
			newGraph.addVertex(v);
		}
		
		for (GraphCutEdge e : edges.keySet()) {
			newGraph.addEdge(e);
		}
		
		return newGraph;
	}
	
	public void setLayout(VisualGraphLayout<GraphCutVertex, GraphCutEdge> layout) {
		this.layout = layout;
	}
	
	@Override
	protected void verticesAdded(Collection<GraphCutVertex> added) {
		for (GraphCutVertex v : added) {
			Namespace ns = v.getNamespace();
			verticesByNamespace.put(ns, v);
			verticesByLevel.get(v.getLevel()).add(v);
		}
		super.verticesAdded(added);
	}
	
	@Override
	protected void verticesRemoved(Collection<GraphCutVertex> removed) {
		for (GraphCutVertex v : removed) {
			Namespace ns = v.getNamespace();
			verticesByNamespace.remove(ns);
			verticesByLevel.get(v.getLevel()).remove(v);
		}
	}
	
}



