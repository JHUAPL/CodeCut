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
 * Borrows from Ghidra file /Features Graph FunctionCalls/src/main/java/functioncalls/graph/job/FcgExpandingVertexCollection.java
 */


package graphcut;

import java.awt.geom.Point2D;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.stream.Collectors;

import edu.uci.ics.jung.algorithms.layout.Layout;
import functioncalls.graph.FcgDirection;

import org.apache.commons.collections4.IterableUtils;
import org.apache.commons.collections4.map.LazyMap;

import ghidra.graph.viewer.GraphViewer;
import util.CollectionUtils;

public class GraphCutExpandingVertexCollection {

	private Comparator<GraphCutVertex> vertexComparator = 
			(v1,v2) -> v1.getID() > v2.getID() ? +1 : v1.getID() < v2.getID() ? -1 : 0;
	private Comparator<GraphCutVertex> sourceVertexComparator = this::compareVerticesByLayoutPosition;
	
	private Map<GraphCutVertex, TreeSet<GraphCutVertex>> newVerticesBySource = LazyMap.lazyMap(
			new TreeMap<>(sourceVertexComparator), () -> new TreeSet<>(vertexComparator));	
	
	private GraphViewer<GraphCutVertex, GraphCutEdge> viewer;
	private GraphCutLevel parentLevel;
	private GraphCutLevel expandingLevel;
	private Set<GraphCutVertex> newVertices;
	private Set<GraphCutEdge> newEdges;
	private Set<GraphCutEdge> indirectEdges = Collections.emptySet();
	private boolean isIncoming;
	private Iterable<GraphCutVertex> sources;
	
	public GraphCutExpandingVertexCollection(Iterable<GraphCutVertex> sources, GraphCutLevel parentLevel, GraphCutLevel expandingLevel,
			Set<GraphCutVertex> newVertices, Set<GraphCutEdge> newEdges, Set<GraphCutEdge> allParentLevelEdges, boolean isIncoming,
			GraphViewer<GraphCutVertex, GraphCutEdge> viewer) {
		
		this.sources = sources;
		this.parentLevel = parentLevel;
		this.newVertices = newVertices;
		this.newEdges = newEdges;
		this.isIncoming = isIncoming;
		this.viewer = viewer;
		this.expandingLevel = expandingLevel;
		
		for(GraphCutEdge e: allParentLevelEdges) {
			
			GraphCutVertex start = e.getStart();
			GraphCutVertex end = e.getEnd();
			GraphCutLevel startLevel = start.getLevel();
			GraphCutLevel endLevel = end.getLevel();
			
			if (expandingLevel.equals(startLevel)) {
				if(expandingLevel.equals(endLevel)) {
					newVerticesBySource.get(start).add(end);
					newVerticesBySource.get(end).add(start);
				}
				else {
					newVerticesBySource.get(end).add(start);
				}
			}
			else {
				newVerticesBySource.get(start).add(end);
			}
		}
	}
	
	private int compareVerticesByLayoutPosition(GraphCutVertex v1, GraphCutVertex v2) {
		
		Layout<GraphCutVertex, GraphCutEdge> layout = viewer.getGraphLayout();
		
		GraphCutLevel l1 = v1.getLevel();
		GraphCutLevel l2 = v2.getLevel();
		
		int result = l1.compareTo(l2);
		if (result != 0) {
			
			if(l1.equals(parentLevel)) {
				return -1;
			}
			if(l2.equals(parentLevel)) {
				return 1;
			}
			
			return result;
		}
		
		Point2D p1 = layout.apply(v1);
		Point2D p2 = layout.apply(v2);
		return (int) (p1.getX() - p2.getX());
	}
	
	public List<GraphCutVertex> getVerticesByLevel(GraphCutLevel level){
		
		Set<GraphCutVertex> existingVertices = newVerticesBySource.keySet();
		
		List<GraphCutVertex> verticesAtLevel = existingVertices.stream().filter(v -> v.getLevel().equals(level)).collect(Collectors.toList());
		return verticesAtLevel;
	}
	
	public List<GraphCutVertex> getAllVerticesAtNewLevel(){
		
		Set<GraphCutVertex> existingVertices = newVerticesBySource.keySet();
		LinkedHashSet<GraphCutVertex> sortedVertices = existingVertices
				.stream()
				.map(v -> newVerticesBySource.get(v))
				.flatMap(set -> set.stream())
				.filter(v -> v.getLevel().equals(expandingLevel))
				.collect(Collectors.toCollection(LinkedHashSet::new));
		return new ArrayList<>(sortedVertices);
		
	}
	
	public Set<GraphCutVertex> getNewVertices(){
		return newVertices;
	}
	
	public Set<GraphCutEdge> getIndirectEdges() {
		return indirectEdges;
	}
	
	public Iterable<GraphCutEdge> getNewEdges(){
		return IterableUtils.chainedIterable(newEdges, indirectEdges);
	}
	
	public int getNewEdgeCount() {
		return newEdges.size() + indirectEdges.size();
	}
	
	public void setIndirectEdges(Set<GraphCutEdge> indirectEdges) {
		this.indirectEdges = CollectionUtils.asSet(indirectEdges);
	}
	
	public GraphCutLevel getExpandingLevel() {
		return expandingLevel;
	}
	
	public FcgDirection getExpandingDirection() {
		return expandingLevel.getDirection();
	}
	
	public Iterable<GraphCutVertex> getSources(){
		return sources;
	}
	
	public boolean isIncoming() {
		return isIncoming;
	}
	
}
