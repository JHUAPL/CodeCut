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
 * Heavily Borrows from /Features Graph FunctionCalls/src/main/java/functioncalls/graph/view/FcgComponent.java
 */

package graphcut;

import edu.uci.ics.jung.visualization.renderers.Renderer;
import functioncalls.graph.FcgEdge;
import functioncalls.graph.FcgVertex;
import generic.theme.GColor;
import ghidra.graph.viewer.GraphComponent;
import ghidra.graph.viewer.GraphViewer;
import ghidra.graph.viewer.SatelliteGraphViewer;
import ghidra.graph.viewer.VisualGraphViewUpdater;
import ghidra.graph.viewer.edge.VisualEdgeRenderer;
import ghidra.graph.viewer.layout.VisualGraphLayout;
import ghidra.graph.viewer.renderer.VisualVertexSatelliteRenderer;
import ghidra.graph.viewer.vertex.VisualVertexRenderer;

/**
 * A graph component for GraphCut
 */
public class GraphCutComponent extends GraphComponent<GraphCutVertex, GraphCutEdge, GraphCutGraph> {
	
	private GraphCutGraph gcGraph;
	
	private GraphCutVertexPaintTransformer vertexPaintTransformer = 
			new GraphCutVertexPaintTransformer(GraphCutVertex.DEFAULT_VERTEX_SHAPE_COLOR);
	
	private GraphCutEdgePaintTransformer edgePaintTransformer =
			new GraphCutEdgePaintTransformer(new GColor("color.bg.plugin.fcg.edge.primary.direct"), 
					new GColor("color.bg.plugin.fcg.edge.primary.indirect"));
	
	private GraphCutEdgePaintTransformer selectedEdgePaintTransformer = 
			new GraphCutEdgePaintTransformer(new GColor("color.bg.plugin.fcg.edge.primary.direct.selected"),
					new GColor("color.bg.plugin.fcg.edge.primary.indirect.selected"));
	
	private GraphCutEdgePaintTransformer satelliteEdgePaintTransformer = 
			new GraphCutEdgePaintTransformer(new GColor("color.bg.plugin.fcg.edge.satellite.direct"),
					new GColor("color.bg.plugin.fcg.edge.satellite.indirect"));
	
	GraphCutComponent(GraphCutGraph g){
		setGraph(g);
		build();
	}
	
	@Override
	protected GraphCutVertex getInitialVertex() {
		return gcGraph.getSource();
	}
	
	@Override
	protected void decoratePrimaryViewer(GraphViewer<GraphCutVertex, GraphCutEdge> viewer, 
			VisualGraphLayout<GraphCutVertex, GraphCutEdge> layout) {
		
		super.decoratePrimaryViewer(viewer, layout);

		Renderer<GraphCutVertex, GraphCutEdge> renderer = viewer.getRenderer();
		VisualVertexRenderer<GraphCutVertex, GraphCutEdge> vertexRenderer =
			(VisualVertexRenderer<GraphCutVertex, GraphCutEdge>) renderer.getVertexRenderer();
		vertexRenderer.setVertexFillPaintTransformer(vertexPaintTransformer);

		VisualEdgeRenderer<GraphCutVertex, GraphCutEdge> edgeRenderer =
			(VisualEdgeRenderer<GraphCutVertex, GraphCutEdge>) renderer.getEdgeRenderer();
		edgeRenderer.setDrawColorTransformer(edgePaintTransformer);
		edgeRenderer.setSelectedColorTransformer(selectedEdgePaintTransformer);
	}
	
	@Override
	protected void decorateSatelliteViewer(SatelliteGraphViewer<GraphCutVertex, GraphCutEdge> viewer,
			VisualGraphLayout<GraphCutVertex, GraphCutEdge> layout) {
		
		super.decorateSatelliteViewer(viewer, layout);
		
		Renderer<GraphCutVertex, GraphCutEdge> renderer = viewer.getRenderer();
		VisualVertexSatelliteRenderer<GraphCutVertex, GraphCutEdge> vertexRenderer = 
				(VisualVertexSatelliteRenderer<GraphCutVertex, GraphCutEdge>) renderer.getVertexRenderer();
		vertexRenderer.setVertexFillPaintTransformer(vertexPaintTransformer);

		VisualEdgeRenderer<GraphCutVertex, GraphCutEdge> edgeRenderer =
			(VisualEdgeRenderer<GraphCutVertex, GraphCutEdge>) renderer.getEdgeRenderer();
		edgeRenderer.setDrawColorTransformer(satelliteEdgePaintTransformer);
	}
	
	@Override
	public void dispose() {
		gcGraph = null;
		super.dispose();
	}
	
	@Override
	public VisualGraphViewUpdater<GraphCutVertex, GraphCutEdge> getViewUpdater(){
		return super.getViewUpdater();
	}
	
	
}
