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
 * Borrows from Ghidra file /Features Graph FunctionCalls/src/main/java/functioncalls/graph/job/BowTieExpandVerticesJob.java
 */

package graphcut;

import java.awt.Rectangle;
import java.awt.Shape;
import java.awt.geom.Point2D;
import java.awt.geom.Rectangle2D;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.common.base.Function;

import edu.uci.ics.jung.algorithms.layout.Layout;
import edu.uci.ics.jung.visualization.RenderContext;
import ghidra.graph.job.AbstractGraphTransitionJob;
import ghidra.graph.viewer.GraphViewer;
import ghidra.graph.viewer.GraphViewerUtils;
import ghidra.util.Msg;



// bowTieExpandVerticesJob
public class GraphCutLayoutExpandVerticesJob extends AbstractGraphTransitionJob<GraphCutVertex, GraphCutEdge> {
	
	private boolean incoming;
	private GraphCutLevel expandingLevel;
	private GraphCutExpandingVertexCollection newVertexCollection;
	
	public GraphCutLayoutExpandVerticesJob(GraphViewer<GraphCutVertex, GraphCutEdge> viewer,
			GraphCutExpandingVertexCollection newVertexCollection, boolean useAnimation) {
		super(viewer, useAnimation);
		
		this.newVertexCollection = newVertexCollection;
		this.incoming = newVertexCollection.isIncoming();
		this.expandingLevel = newVertexCollection.getExpandingLevel();
		
		if(!(graphLayout instanceof GraphCutLayout)) {
			throw new IllegalArgumentException("The current graph layout must be the GraphCut Layout to use this job");
		}
		
		Msg.trace(this, "\n Layout Expand Job - new vertices: " + newVertexCollection.getNewVertices());
	}
	
	@Override
	protected boolean isTooBigToAnimate() {
		return graph.getVertexCount() > 1000;
	}
	
	@Override
	protected void updateOpacity(double percentComplete) {
		double x = percentComplete;
		double x2 = x*x;
		double remaining = 1-percentComplete;
		double y = x2 - remaining;
		
		Set<GraphCutVertex> newVertices = newVertexCollection.getNewVertices();
		
		double vertexAlpha = x;
		double edgeAlpha  = Math.max(y, 0);
		for(GraphCutVertex v : newVertices) {
			v.setAlpha(vertexAlpha);
		}
		
		Iterable<GraphCutEdge> newEdges = newVertexCollection.getNewEdges();
		for(GraphCutEdge e : newEdges) {
			e.setAlpha(edgeAlpha);
		}
		
	}
	
	@Override
	public boolean canShortcut() {
		return true;
	}
	
	@Override
	public void shortcut() {
		isShortcut = true;
		
		if(vertexLocations.isEmpty()) {
			initializeVertexLocations();
		}
		
		stop();
	}
	
	@Override
	protected void initializeVertexLocations() {
		Map<GraphCutVertex, TransitionPoints> destinationLocations = createDestinationLocation();
		vertexLocations.putAll(destinationLocations);
	}
	
	private Map<GraphCutVertex, TransitionPoints> createDestinationLocation(){
		
		Map<GraphCutVertex, Point2D> finalDestinations = arrangeNewVertices();
		
		Map<GraphCutVertex, TransitionPoints> transitions = new HashMap<>();
		GraphCutLevel parentLevel = expandingLevel.parent();
		Iterable<GraphCutEdge> newEdges = newVertexCollection.getNewEdges();
		Set<GraphCutVertex> newVertices = newVertexCollection.getNewVertices();
		for(GraphCutEdge e : newEdges) {
			GraphCutVertex newVertex = incoming ? e.getStart() : e.getEnd();
			if(!finalDestinations.containsKey(newVertex)) {
				continue;
			}
			if(!newVertices.contains(newVertex)) {
				continue;
			}
			
			GraphCutVertex existingVertex = incoming ? e.getEnd() : e.getStart();
			GraphCutLevel existingLevel = existingVertex.getLevel();
			if (!existingLevel.equals(parentLevel)) {
				continue;
			}
			
			Point2D start = (Point2D) toLocation(existingVertex).clone();
			Point2D end = finalDestinations.get(newVertex);
			
			TransitionPoints trans = new TransitionPoints(start, end);
			transitions.put(newVertex, trans);
		}
		return transitions;
		
	}
	
	
	private Map<GraphCutVertex, Point2D> arrangeNewVertices(){
		
		GraphCutLayout bowTie = (GraphCutLayout) graphLayout;
		boolean isCondensed = bowTie.isCondensedLayout();
		int widthPadding = isCondensed ? GraphViewerUtils.EXTRA_LAYOUT_COLUMN_SPACING_CONDENSED :
			GraphViewerUtils.EXTRA_LAYOUT_COLUMN_SPACING;
		
		widthPadding *= expandingLevel.getDistance();
		int heightPadding = calculateHeightPadding(isCondensed);
		
		GraphCutLevel parentLevel = expandingLevel.parent();
		List<GraphCutVertex> parentLevelVertices = newVertexCollection.getVerticesByLevel(parentLevel);
		if(parentLevelVertices.isEmpty()) {
			return Collections.emptyMap();
		}
		
		Rectangle existingRowBounds = getBounds(parentLevelVertices);
		Msg.trace(this, "existing row bounds " + existingRowBounds);
		double existingY = existingRowBounds.y;
		double existingCenterX = existingRowBounds.x + (existingRowBounds.width/2);
		
		List<GraphCutVertex> allLevelVertices = newVertexCollection.getAllVerticesAtNewLevel();
		double newRowWidth = getWidth(allLevelVertices, widthPadding);
		double newRowHeight = getHeight(allLevelVertices);
		double newRowX = existingCenterX - (newRowWidth/2);
		
		double newRowY = 0;
		if(newVertexCollection.isIncoming()) {
			newRowY = existingY - newRowHeight - heightPadding;
		}
		else {
			newRowY = existingY +existingRowBounds.height + heightPadding;
		}
		
		Msg.trace(this, "new row bounds " + new Rectangle2D.Double(newRowX, newRowY, newRowWidth, newRowHeight));
		
		Map<GraphCutVertex, Point2D> locations = getExistingLocations(allLevelVertices);
		if(!locations.isEmpty()) {
			return locations;
		}
		
		RenderContext<GraphCutVertex, GraphCutEdge> renderContext = viewer.getRenderContext();
		Function<? super GraphCutVertex, Shape> shaper = renderContext.getVertexShapeTransformer();
		
		double x = newRowX;
		double y = newRowY;
		
		int n = allLevelVertices.size();
		
		//Dynamic Layout
		Set<GraphCutVertex> placed = new HashSet<>();
		Set<GraphCutVertex> newVertices = newVertexCollection.getNewVertices();
		//Make shallow copy
		List<GraphCutVertex> allLevelVerticesOrig = new ArrayList<>();
		for(GraphCutVertex v : allLevelVertices) {
			allLevelVerticesOrig.add(v);
		}
		// 1. Place visible vertices
		for(GraphCutVertex v: allLevelVerticesOrig) {
			if(v.visible) {
				GraphCutVertex tmpVertex = allLevelVertices.get(v.layoutIndex);
				int tmpIndex = allLevelVertices.indexOf(v);
				allLevelVertices.set(v.layoutIndex, v);
				allLevelVertices.set(tmpIndex, tmpVertex);
				placed.add(v);
			}
		}
		// 2. Place newVertices
		for(GraphCutVertex v: newVertices) {
			if(placed.contains(v)) {
				continue;
			}
			placed.add(v);
			int index = findEmptyLayoutIndex(allLevelVertices);
			v.layoutIndex = index;
			v.visible = true;
			GraphCutVertex tmpVertex = allLevelVertices.get(index);
			int tmpIndex = allLevelVertices.indexOf(v);
			allLevelVertices.set(tmpIndex, tmpVertex);
			allLevelVertices.set(v.layoutIndex, v);
			
		}
		
		// 3. Place all invisible vertices randomly
		int curr = 0;
		for(GraphCutVertex v: allLevelVerticesOrig) {
			if(placed.contains(v)) {
				continue;
			}
			//find empty spot
			while(allLevelVertices.get(curr).visible) {
				curr++;
			}
			allLevelVertices.set(curr, v);
		}
		

		
		for(int i = 0; i < n; i++) {
			GraphCutVertex v = allLevelVertices.get(i);
			Rectangle myBounds = shaper.apply(v).getBounds();
			double myHalf = myBounds.width / 2;
			
			double nextHalf = 0;
			boolean isLast = i == n-1;
			if(!isLast) {
				GraphCutVertex nextV = allLevelVertices.get(i+1);
				Rectangle nextBounds = shaper.apply(nextV).getBounds();
				nextHalf = nextBounds.width/2;
			}
			
			Point2D p = new Point2D.Double(x,y);
			locations.put(v, p);
			
			double vWidth = myHalf + widthPadding + nextHalf;
			Msg.trace(this, v + " at x,width: "+x+","+vWidth);
			x+=vWidth;
		}
		
		return locations;
	}
	
	private int findEmptyLayoutIndex(List<GraphCutVertex> vertices) {
		//Check middle
		int mid = vertices.size()/2;
		if(!vertices.get(mid).visible) {
			return mid;
		}
		
		// start checking both sides
		int left = mid-1;
		int right = mid+1;
		while(left >= 0 || right <=vertices.size()-1) {
			if(left>=0 && !vertices.get(left).visible) {
				return left;
			}
			left--;
			if(right <= vertices.size()-1 && !vertices.get(right).visible) {
				return right;
			}
			right++;

		}
		return -1;
	}
	
	
	private int calculateHeightPadding(boolean isCondensed) {
		
		int basePadding = isCondensed ? GraphViewerUtils.EXTRA_LAYOUT_ROW_SPACING_CONDENSED
				: GraphViewerUtils.EXTRA_LAYOUT_ROW_SPACING;

		double separationFactor = expandingLevel.getDistance();
		
		List<GraphCutVertex> allLevelVertices = newVertexCollection.getAllVerticesAtNewLevel();
		int count = allLevelVertices.size();
		
		double to = 1.25;
		double power = Math.pow(separationFactor, to);
		int maxPadding = (int) (basePadding * power);
		
		int delta = maxPadding - basePadding;
		double percent = Math.min(count / 20f,  1);
		int padding = basePadding + (int) (delta * percent);
		return padding;
	}
	
	
	private Map<GraphCutVertex, Point2D> getExistingLocations(List<GraphCutVertex> vertices){
		Map<GraphCutVertex, Point2D> locations = new HashMap<>();
		for(GraphCutVertex v: vertices) {
			Point2D p = toLocation(v);
			if (p.getX() == 0 && p.getY() == 0) {
				return new HashMap<>();
			}
			
			locations.put(v, (Point2D) p.clone());
		}
		return locations;
	}
	
	
	
	private Rectangle getBounds(List<GraphCutVertex> vertices) {
		RenderContext<GraphCutVertex, GraphCutEdge> renderContext = viewer.getRenderContext();
		Function<? super GraphCutVertex, Shape> shaper = renderContext.getVertexShapeTransformer();
		
		Layout<GraphCutVertex, GraphCutEdge> layout = viewer.getGraphLayout();
		
		Rectangle area = null;
		for (GraphCutVertex v : vertices) {
			Rectangle bounds = shaper.apply(v).getBounds();
			Point2D loc = layout.apply(v);
			int x = (int) loc.getX();
			int y = (int) loc.getY();
			bounds.setLocation(x,y);
			if(area == null) {
				area = bounds;
			}
			area.add(bounds);
		}
		
		return area;
	}
	
	
	private int getWidth(List<GraphCutVertex> vertices, int widthPadding) {
		RenderContext<GraphCutVertex, GraphCutEdge> renderContext  = viewer.getRenderContext();
		Function<? super GraphCutVertex, Shape> shaper = renderContext.getVertexShapeTransformer();
		
		int width = 0;
		for (GraphCutVertex v : vertices) {
			width += shaper.apply(v).getBounds().width + widthPadding;
		}
		
		return width;
	}
	
	private int getHeight(List<GraphCutVertex> vertices) {
		RenderContext<GraphCutVertex, GraphCutEdge> renderContext = viewer.getRenderContext();
		Function<? super GraphCutVertex, Shape> shaper = renderContext.getVertexShapeTransformer();
		
		int height = 0;
		for (GraphCutVertex v: vertices) {
			height = Math.max(height, shaper.apply(v).getBounds().height);
		}
		return height;
	}
	
}
