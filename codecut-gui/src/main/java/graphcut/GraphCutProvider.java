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
 * Borrows from Ghidra file /Features Graph FunctionCalls/src/main/java/functioncalls/plugin/FcgProvider.java
 */


package graphcut;

import static functioncalls.graph.FcgDirection.*;

import java.awt.*;
import java.awt.event.KeyEvent;
import java.awt.event.MouseEvent;
import java.util.*;
import java.util.List;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import javax.swing.*;

import org.apache.commons.collections4.IterableUtils;

import com.google.common.cache.RemovalNotification;

import codecutguiv2.CodeCutGUIPlugin;
import docking.*;
import docking.action.*;
import docking.menu.ActionState;
import docking.menu.MultiStateDockingAction;
import docking.widgets.EventTrigger;
import docking.widgets.OptionDialog;
import functioncalls.graph.*;
import ghidra.app.context.NavigationActionContext;
import ghidra.graph.VisualGraphComponentProvider;
import ghidra.graph.viewer.*;
import ghidra.graph.viewer.actions.VgVertexContext;
import ghidra.graph.viewer.event.mouse.VertexMouseInfo;
import ghidra.graph.viewer.layout.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import resources.Icons;
import resources.ResourceManager;
import util.CollectionUtils;

/**
 * The primary component provider for the GraphCutPlugin
 */
public class GraphCutProvider 
	extends VisualGraphComponentProvider<GraphCutVertex, GraphCutEdge, GraphCutGraph> {
	
	private static final ImageIcon ICON = ResourceManager.loadImage("images/function_graph.png");
	
	// A limit for displayed references
	public static final int MAX_REFERENCES = 100;
	
	private static final String TOOLBAR_GROUP_A = "A";
	private static final String TOOLBAR_GROUP_B = "B";
	
	private static final String MENU_GROUP_EXPAND = "A";
	private static final String MENU_GROUP_GRAPH = "B";
	
	private static final String NAME = "CodeCut Graph";
	
	private JComponent component;
	private CodeCutGUIPlugin plugin;
	
	private GraphCutView view;
	private LayoutProvider<GraphCutVertex, GraphCutEdge, GraphCutGraph> defaultLayoutProvider = new GraphCutLayoutProvider();
	private LayoutProvider<GraphCutVertex, GraphCutEdge, GraphCutGraph> layoutProvider;
	private Set<LayoutProvider<GraphCutVertex, GraphCutEdge, GraphCutGraph>> layouts = new HashSet<>();
	
	private GraphCutDataFactory dataFactory;
	private GraphCutData graphData;
	
	private GraphCutExpansionListener expansionListener = new ExpansionListener();
	
	private Predicate<GraphCutEdge> unfiltered = v -> true;
	private Predicate<GraphCutEdge> edgeNotInGraphFilter = e -> !graphData.getGraph().containsEdge(e);
	private Predicate<GraphCutVertex> vertexInGraphFilter = v -> graphData.getGraph().containsVertex(v);
	
	private ToggleDockingAction navigateIncomingToggleAction;
	
	public HashMap<Namespace, ArrayList<Function>> functionsByNamespace = new HashMap<>();
	public Set<Namespace> FilterWhitelist = new HashSet<>();
	
	public GraphCutProvider(Tool tool, CodeCutGUIPlugin plugin) {
		super(tool, NAME, plugin.getName());
		this.plugin = plugin;
		
		
		dataFactory = new GraphCutDataFactory(this::graphDataCacheRemoved);
		graphData = dataFactory.create(null);
		
		buildComponent();
		
		// If you want icon in toolbar and key shortcut 
		//setIcon(ICON);
		//addToToolbar();
		//setKeyBinding(new KeyBindingData(KeyEvent.VK_G, DockingUtils.CONTROL_KEY_MODIFIER_MASK));
		
		setWindowMenuGroup(CodeCutGUIPlugin.GRAPH_NAME);
		setWindowGroup(CodeCutGUIPlugin.GRAPH_NAME);
		setDefaultWindowPosition(WindowPosition.WINDOW);
		
		setHelpLocation(CodeCutGUIPlugin.DEFAULT_HELP);
		
		addToTool();
		addSatelliteFeature();
		
		createLayouts();
		createActions();
		
	}
	
	private void buildFunctionsByNamespace(){
		ProgramLocation loc = plugin.getCurrentLocation();
		Program p = loc.getProgram();
		FunctionManager fm = p.getFunctionManager();
		FunctionIterator it = fm.getFunctions(true);
		
		while (it.hasNext()) {
			Function f = it.next();
			Namespace parent = f.getParentNamespace();
			if(functionsByNamespace.get(parent) == null) {
				//key does not exist yet
				functionsByNamespace.put(parent, new ArrayList<Function>());
			}
			
			functionsByNamespace.get(parent).add(f);
		}

	}
	
	
	@Override
	public GraphCutView getView() {
		return view;
	}
	
	@Override
	public void componentShown() {
		installGraph();
	}
	
	public void optionsChanged() {
		view.optionsChanged();
	}
	
	public void locationChanged(ProgramLocation loc) {
		if(!navigateIncomingToggleAction.isSelected()) {
			return;
		}
		
		if(loc == null) {
			setNamespace(null);
			return;
		}
		
		Program p = loc.getProgram();
		FunctionManager fm = p.getFunctionManager();
		Function f = fm.getFunctionContaining(loc.getAddress());
		if(f == null) {
			return;
		}
		Namespace ns = f.getParentNamespace();
		setNamespace(ns);
	}
	
	void setNamespace(Namespace ns) {
		if(graphData.isNamespace(ns)) {
			return;
		}
		
		saveCurrentGraphPerspective();
		createAndInstallGraph(ns);
		updateTitle();
	}
	
	private void saveCurrentGraphPerspective() {
		if (!isVisible()) {
			return;
		}
		if(!graphData.hasResults()) {
			return;
		}
		if(view.getGraphComponent().isUninitialized()) {
			return;
		}
		
		GraphPerspectiveInfo<GraphCutVertex, GraphCutEdge> info = view.generateGraphPerspective();
		graphData.setGraphPerspective(info);
	}
	
	private void updateTitle() {
		setTitle(NAME);
		String subTitle = null;
		if(graphData.hasResults()) {
			GraphCutGraph graph = graphData.getGraph();
			subTitle = graphData.getNamespace().getName() + " ("+graph.getVertexCount() + " namespaces; " + graph.getEdgeCount() + " edges)";
		}
		setSubTitle(subTitle);
	}
	
	public void rebuildCurrentGraph() {
		if (!graphData.hasResults()) {
			return;
		}
		
		//Mark all nodes as invisible
		GraphCutGraph g = graphData.getGraph();
		Iterator<GraphCutVertex> it = g.getAllVertices();
		while(it.hasNext()) {
			GraphCutVertex v = it.next();
			v.visible = false;
		}

		Namespace namespace = graphData.getNamespace();
		dataFactory.remove(namespace);
		createAndInstallGraph(namespace);
	}
	
	private void createAndInstallGraph(Namespace namespace) {
		graphData = dataFactory.create(namespace);
		if(!isVisible()) {
			return;
		}
		installGraph();
	}
	
	private void installGraph() {
		if (!graphData.hasResults()) {
			Address address = plugin.getCurrentAddress();
			if(address == null) {
				view.showErrorView("No namespace selected");
			}
			else {
				view.showErrorView("No namespace containing " +address);
			}
			return;
		}
		
		buildFunctionsByNamespace();
		
		if(graphData.isInitialized()) {
			view.setGraph(graphData.getGraph());
			view.setGraphPerspective(graphData.getGraphPerspective());
			return;
		}
		
		GraphCutGraph graph = graphData.getGraph();
		setLayout(graph);
		
		GraphCutLevel source = GraphCutLevel.sourceLevel();
		GraphCutVertex sourceVertex = new GraphCutVertex(graphData.getNamespace(), source, expansionListener);
		graph.setSource(sourceVertex);
		trackNamespaceEdges(sourceVertex);
		
		view.setGraph(graph);
		GraphCutComponent gc = view.getGraphComponent();
		gc.setVertexFocused(sourceVertex);
		
		if(sourceVertex.canExpandIncomingReferences()) {
			expand(sourceVertex, IN);
		}
		
		if(sourceVertex.canExpandOutgoingReferences()) {
			expand(sourceVertex, OUT);
		}
		
	}
	
	private GraphCutVertex getOrCreateVertex(Namespace ns, GraphCutLevel level) {
		GraphCutGraph graph = graphData.getGraph();
		GraphCutVertex v = graph.getVertex(ns);
		if(v != null) {
			return v;
		}
		
		v = new GraphCutVertex(ns, level, expansionListener);
		trackNamespaceEdges(v);
		return v;
	}
	
	private void graphDataCacheRemoved(RemovalNotification<Namespace, GraphCutData> notification) {
		GraphCutData data = notification.getValue();
		data.dispose();
	}
	
	private void setLayout(GraphCutGraph g) {
		try {
			VisualGraphLayout<GraphCutVertex, GraphCutEdge> layout = 
					layoutProvider.getLayout(g, TaskMonitor.DUMMY);
			g.setLayout(layout);
			view.setLayoutProvider(layoutProvider);
		}
		catch(CancelledException e) {
			// can't happen
		}
	}
	
	private void buildComponent() {
		view = new GraphCutView(plugin.getOptions());
		
		//double click happened
		view.setVertexClickListener((v, info) -> {
			if(!isNavigatableArea(info)) {
				return false;
			}
			
			Namespace ns = v.getNamespace();
			ArrayList<Function> fun_arr = functionsByNamespace.get(ns);
			if(fun_arr == null || fun_arr.isEmpty()) {
				return true;
			}

			Function f = fun_arr.get(0);
			Address entry = f.getEntryPoint();
			Program p = f.getProgram();
			plugin.handleProviderLocationChanged(new ProgramLocation(p, entry));
			return true;
		});
		
		view.setTooltipProvider(new GraphCutTooltipProvider());
		
		JComponent viewComponent = view.getViewComponent();
		component = new JPanel(new BorderLayout());
		component.add(viewComponent, BorderLayout.CENTER);
	}
	
	private boolean isNavigatableArea(VertexMouseInfo<GraphCutVertex, GraphCutEdge> info) {
		Component clickedComponent = info.getClickedComponent();
		if(clickedComponent instanceof JButton) {
			return false;
		}
		
		int buffer = 10;
		MouseEvent e = info.getTranslatedMouseEvent();
		Point p = e.getPoint();
		if(p.x < buffer || p.y < buffer) {
			return false;
		}
		
		Rectangle bounds = clickedComponent.getBounds();
		if (bounds.width - p.x < buffer || bounds.height - p.y < buffer) {
			return false;
		}
		
		return true;
	}
	
	@Override
	public JComponent getComponent() {
		return component;
	}
	
	@Override
	public void dispose() {
		dataFactory.dispose();
		graphData.dispose();
		functionsByNamespace.clear();
		FilterWhitelist.clear();
		super.dispose();
	}
	
	@Override
	public Class<?> getContextType(){
		return NavigationActionContext.class;
	}
	
	public GraphCutGraph getGraph() {
		if(graphData.hasResults()) {
			return graphData.getGraph();
		}
		return null;
	}
	
	private void createLayouts() {
		//Off the shelf layouts
		layouts.addAll(JungLayoutProviderFactory.createLayouts());
		
		//specialized layout
		layouts.add(defaultLayoutProvider);
		layoutProvider = defaultLayoutProvider;
	}
	
	private void createActions() {
		
		addLayoutAction();
		
		DockingAction collapseIn = new CollapseAction("Hide Incoming Edges", IN);
		DockingAction collapseOut = new CollapseAction("Hide Outgoing Edges", OUT);

		DockingAction expandIn = new ExpandAction("Show Incoming Edges", IN);
		DockingAction expandOut = new ExpandAction("Show Outgoing Edges", OUT);

		DockingAction collapseLevelIn = new CollapseLevelAction("Hide Incoming Level Edges", IN);
		DockingAction collapseLevelOut = new CollapseLevelAction("Hide Outgoing Level Edges", OUT);

		DockingAction expandLevelIn = new ExpandLevelAction("Show Incoming Level Edges", IN);
		DockingAction expandLevelOut = new ExpandLevelAction("Show Outgoing Level Edges", OUT);

		// ExpandLevelAction

		addLocalAction(collapseIn);
		addLocalAction(collapseOut);
		addLocalAction(collapseLevelIn);
		addLocalAction(collapseLevelOut);
		addLocalAction(expandIn);
		addLocalAction(expandOut);
		addLocalAction(expandLevelIn);
		addLocalAction(expandLevelOut);
		
		navigateIncomingToggleAction = 
				new ToggleDockingAction("Navigate on Incoming Location Changes", plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				//nothing
			}
			
			@Override
			public void setSelected(boolean newValue) {
				super.setSelected(newValue);
				if(isSelected()) {
					locationChanged(plugin.getCurrentLocation());
				}
			}
		};
		
		navigateIncomingToggleAction.setSelected(true);
		navigateIncomingToggleAction.setToolBarData(
				new ToolBarData(Icons.NAVIGATE_ON_INCOMING_EVENT_ICON, TOOLBAR_GROUP_A));
		navigateIncomingToggleAction.setDescription(
			"<html>Incoming Navigation<br><br>Toggle <b>On</b>  - change the graphed " +
				"namespace on Listing navigation events" +
				"<br>Toggled <b>Off</b> - don't change the graph on Listing navigation events");
		navigateIncomingToggleAction.setHelpLocation(
			new HelpLocation(plugin.getName(), "Navigation_Incoming"));
		addLocalAction(navigateIncomingToggleAction);
		
		DockingAction graphNamespaceAction = 
				new DockingAction("Graph Node Namespace Calls", plugin.getName()) {
			
					@Override
					public void actionPerformed(ActionContext context) {
						VgVertexContext<GraphCutVertex> vContext = getVertexContext(context);
						GraphCutVertex v = vContext.getVertex();
						setNamespace(v.getNamespace());
					}
					
					@Override
					public boolean isEnabledForContext(ActionContext context) {
						VgVertexContext<GraphCutVertex> vContext = getVertexContext(context);
						if(vContext == null) {
							return false;
						}
						
						GraphCutVertex v = vContext.getVertex();
						Namespace namespace = v.getNamespace();
						Namespace graphedNamespace = graphData.getNamespace();
						
						boolean isEnabled = !namespace.equals(graphedNamespace);
						if(isEnabled) {
							setPopupMenuData(
									new MenuData(new String[] {"Graph '" + namespace.getName() + "'"}, 
									MENU_GROUP_GRAPH));
							
						}
						return isEnabled;
					}
				};
			
			graphNamespaceAction.setPopupMenuData(
					new MenuData(new String [] {"Graph Namespace"}, MENU_GROUP_GRAPH));
			addLocalAction(graphNamespaceAction);
			
	}
	
	private Collection<GraphCutEdge> getGraphEdges(GraphCutVertex v, FcgDirection direction){
		
		GraphCutGraph graph = graphData.getGraph();
		if(direction == IN) {
			return graph.getInEdges(v);
		}
		return graph.getOutEdges(v);
	}
	
	//return edges that we know about, but may not be graphed
	private Set<GraphCutEdge> getModelEdges(Iterable<GraphCutVertex> vertices, GraphCutLevel level, Predicate<GraphCutEdge> filter){
		
		FcgDirection direction = level.getDirection();
		if (direction == IN) {
			return getIncomingEdges(vertices, level, filter);
		}
		return getOutgoingEdges(vertices, level, filter);
	}
	
	private VgVertexContext<GraphCutVertex> getVertexContext(ActionContext c){
		if(!(c instanceof VgVertexContext)) {
			return null;
		}
		
		@SuppressWarnings("unchecked")
		VgVertexContext<GraphCutVertex> vContext = (VgVertexContext<GraphCutVertex>) c;
		return vContext;
	}
	
	
	//============================================================================
	// Layout Methods
	//============================================================================
		
	static final String RELAYOUT_GRAPH_ACTION_NAME = "Relayout Graph";
	
	private void addLayoutAction() {
		DockingAction resetGraphAction = new DockingAction("Reset Graph", plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				int choice = OptionDialog.showYesNoDialog(getComponent(), "Reset graph?", "Erase all vertex position information?");
				if(choice != OptionDialog.YES_OPTION) {
					return;
				}
				
				rebuildCurrentGraph();
			}
		};
		resetGraphAction.setToolBarData(new ToolBarData(Icons.REFRESH_ICON));
		resetGraphAction
				.setDescription("Resets the graph -- All positioning will be lost");
		resetGraphAction.setHelpLocation(new HelpLocation("GraphCutPlugin", "Relayout_Graph"));
		
		addLocalAction(resetGraphAction);
		
		MultiStateDockingAction<LayoutProvider<GraphCutVertex, GraphCutEdge, GraphCutGraph>> layoutAction = 
				new MultiStateDockingAction<>(RELAYOUT_GRAPH_ACTION_NAME, plugin.getName()) {
			
			@Override
			public void actionPerformed(ActionContext context) {
				LayoutProvider<GraphCutVertex, GraphCutEdge, GraphCutGraph> currentUserData = getCurrentUserData();
				changeLayout(currentUserData);
			}
			
			@Override
			public void actionStateChanged(
					ActionState<LayoutProvider<GraphCutVertex, GraphCutEdge, GraphCutGraph>> newActionState,
					EventTrigger trigger) {
				changeLayout(newActionState.getUserData());
			}
		};
		
		layoutAction.setGroup(TOOLBAR_GROUP_B);
		
		addLayoutProviders(layoutAction);
		
		//can also addLocalAction(layoutAction) for debug
	}
	
	private void addLayoutProviders(MultiStateDockingAction<LayoutProvider<GraphCutVertex, GraphCutEdge, GraphCutGraph>> layoutAction) {
		
		for(LayoutProvider<GraphCutVertex, GraphCutEdge, GraphCutGraph> l: layouts) {
			layoutAction.addActionState(new ActionState<>(l.getLayoutName(), l.getActionIcon(), l));
		}
		
		layoutAction.setCurrentActionStateByUserData(defaultLayoutProvider);
	}
	
	private void changeLayout(LayoutProvider<GraphCutVertex, GraphCutEdge, GraphCutGraph> provider) {
		this.layoutProvider = provider;
		if(isVisible()) {
			rebuildCurrentGraph();
		}
	}
	
	private Iterable<GraphCutVertex> getVerticesByLevel(GraphCutLevel level){
		GraphCutGraph graph = graphData.getGraph();
		return graph.getVerticesByLevel(level);
	}
	
	private void trackNamespaceEdges(GraphCutVertex v) {
		Namespace ns = v.getNamespace();
		NamespaceEdgeCache edgeCache = graphData.getNamespaceEdgeCache();
		if(edgeCache.isTracked(ns)) {
			return; //already tracked
		}
		edgeCache.setTracked(ns);
		
		Set<Namespace> calling = nsGetCallingNamespaces(ns);
		int count = calling.size();
		if (count > MAX_REFERENCES) {
			v.setTooManyIncomingReferences(true);
			v.setHasIncomingReferences(true);
		}
		else {
			trackNamespaceIncomingEdges(v, calling);
			v.setHasIncomingReferences(!calling.isEmpty());
		}
		
		Set<Namespace> called = nsGetCalledNamespaces(ns);
		count = called.size();
		if(count > MAX_REFERENCES) {
			v.setTooManyOutgoingReferences(true);
			v.setHasOutgoingReferences(true);
		}
		else {
			trackNamespaceOutgoingEdges(v,called);
			v.setHasOutgoingReferences(true);
		}
	}
	
	private void trackNamespaceOutgoingEdges(GraphCutVertex v, Set<Namespace> local_calledNamespaces) {
		NamespaceEdgeCache edgeCache = graphData.getNamespaceEdgeCache();
		Namespace ns = v.getNamespace();
		for(Namespace callee : local_calledNamespaces) {
			edgeCache.get(ns).add(new NamespaceEdge(ns, callee));
		}
	}
	
	private void trackNamespaceIncomingEdges(GraphCutVertex v, Set<Namespace> local_callingNamespaces) {
		NamespaceEdgeCache edgeCache = graphData.getNamespaceEdgeCache();
		Namespace ns = v.getNamespace();
		for(Namespace caller : local_callingNamespaces) {
			edgeCache.get(ns).add(new NamespaceEdge(caller, ns));
		}
	}
	
	
	/**
	 * The equivalent of f.getCallingFunctions but for namespaces
	 * @param ns the namespace 
	 * @return namespaces that "call" this namespace
	 */
	public Set<Namespace> nsGetCallingNamespaces(Namespace ns){
		Set<Namespace> set = new HashSet<Namespace>();
		
		for(Function f: functionsByNamespace.get(ns)) { // for every function in our namespace
			Set<Function> calling = f.getCallingFunctions(TaskMonitor.DUMMY);
			for(Function called: calling) { // look at every function that calls it
				Namespace parent = called.getParentNamespace();
				boolean wantToAdd = FilterWhitelist.isEmpty() || FilterWhitelist.contains(parent);
				if(wantToAdd) {
					set.add(parent); //add their namespace to the "calling namespaces"
				}
			}
		}
		return set;
	}
	
	
	/**
	 * the equivalent of f.getCalledFunctions but for namespaces
	 * @param ns the namespace
	 * @return namespaces that this namespace "calls"
	 */
	public Set<Namespace> nsGetCalledNamespaces(Namespace ns){
		Set<Namespace> set = new HashSet<Namespace>();
		
		for(Function f: functionsByNamespace.get(ns)) { // for every function in our namespace
			Set<Function> called = f.getCalledFunctions(TaskMonitor.DUMMY);
			for(Function calling: called) { //look at every function that it calls
				Namespace parent = calling.getParentNamespace();
				boolean wantToAdd = FilterWhitelist.isEmpty() || FilterWhitelist.contains(parent);
				if(wantToAdd) {
					set.add(parent);// add their namespace to the "called namespaces"
				}
			}
		}
		return set;
	}
	
	//============================================================================
	// Expand/Collapse Methods
	//============================================================================
	
	private void expand(GraphCutVertex source, FcgDirection direction) {
		GraphCutLevel level = source.getLevel();
		expand(CollectionUtils.asIterable(source), level, direction);
	}
	
	private void expand(Iterable<GraphCutVertex> sources,GraphCutLevel sourceLevel, FcgDirection direction) {
		sources = IterableUtils.filteredIterable(sources, v -> v.canExpand());
		if(IterableUtils.isEmpty(sources)) {
			return;
		}
		
		GraphCutLevel expandingLevel = sourceLevel.child(direction);
		Set<GraphCutEdge> newEdges = getModelEdges(sources, expandingLevel, edgeNotInGraphFilter);
		
		Iterable<GraphCutVertex> sourceSiblings = getVerticesByLevel(sourceLevel);
		Set<GraphCutEdge> parentLevelEdges = getModelEdges(sourceSiblings, expandingLevel, unfiltered);
		
		Set<GraphCutVertex> newVertices = toVertices(newEdges, direction, vertexInGraphFilter.negate());
		boolean isIncoming = direction == IN;
		GraphCutExpandingVertexCollection collection = 
				new GraphCutExpandingVertexCollection(sources, sourceLevel, expandingLevel, newVertices, newEdges, parentLevelEdges, isIncoming, view.getPrimaryGraphViewer());
		
		doExpand(collection);
		markExpanded(sources, direction, true);
	}
	
	private void markExpanded(Iterable<GraphCutVertex> vertices, FcgDirection direction, boolean expanded) {
		if (direction == IN) {
			markInsExpanded(vertices, expanded);
		}
		else {
			markOutsExpanded(vertices, expanded);
		}

		component.repaint();
	}
	
	private void markInsExpanded(Iterable<GraphCutVertex> vertices, boolean expanded) {
		for(GraphCutVertex v: vertices){
			if(expanded != v.isIncomingExpanded()) {
				v.setIncomingExpanded(expanded);
			}
		}
	}
	
	private void markOutsExpanded(Iterable<GraphCutVertex> vertices, boolean expanded) {
		for(GraphCutVertex v: vertices) {
			if(expanded != v.isOutgoingExpanded()) {
				v.setOutgoingExpanded(expanded);
			}
		}
	}
	
	private void collapseLevel(GraphCutLevel level, FcgDirection direction) {
		
		GraphCutLevel collapseLevel = level.child(direction);
		Iterable<GraphCutVertex> toRemove = getVerticesAtOrGreaterThan(collapseLevel);
		
		Set<GraphCutVertex> set = util.CollectionUtils.asSet(toRemove.iterator());
		GraphCutGraph graph = graphData.getGraph();
		graph.removeVertices(set);
		component.repaint();
		
		updateTitle();
		
		Iterable<GraphCutVertex> sources = graph.getVerticesByLevel(level);
		markExpanded(sources, direction, false);
	}
	
	private void collapse(GraphCutVertex v, FcgDirection direction) {
		
		Collection<GraphCutEdge> edges =  new HashSet<>(getGraphEdges(v, direction));
		GraphCutGraph graph = graphData.getGraph();
		for (GraphCutEdge e: edges) {
			
			GraphCutVertex other = getOtherEnd(v,e);
			if(isDependent(v, other, e)) {
				graph.removeEdge(e);
				
				collapse(other, direction);
				removeFromGraph(other);
			}
		}
		markExpanded(CollectionUtils.asIterable(v), direction, false);
	}
	
	private GraphCutVertex getOtherEnd(GraphCutVertex v, GraphCutEdge e) {
		GraphCutVertex start = e.getStart();
		if(v.equals(start)) {
			return e.getEnd();
		}
		return start;
	}
	
	private boolean isDependent(GraphCutVertex parent, GraphCutVertex other, GraphCutEdge e) {
		GraphCutLevel parentLevel = parent.getLevel();
		GraphCutLevel otherLevel = other.getLevel();
		if(!parentLevel.isParentOf(otherLevel)) {
			return false;
		}
		
		//we are a dependent
		GraphCutGraph g = graphData.getGraph();
		Collection<GraphCutEdge> ins = g.getInEdges(other);
		for(GraphCutEdge inEdge : ins) {
			GraphCutVertex start = inEdge.getStart();
			if(start.equals(parent)) {
				continue;
			}
			
			GraphCutLevel inLevel = start.getLevel();
			if(!inLevel.equals(parentLevel)) {
				continue;
			}
			
			if(start.isExpanded()) {
				return false;
			}
		}
		return true;
	}
	
	private void removeFromGraph(GraphCutVertex v){
		GraphCutGraph g = graphData.getGraph();
		g.removeVertex(v);
		component.repaint();
	}
	
	private Set<GraphCutEdge> getIncomingEdges(Iterable<GraphCutVertex> vertices, GraphCutLevel level, Predicate<GraphCutEdge> filter){
		Map<Namespace, GraphCutVertex> newVertexCache = new HashMap<>();
		Set<GraphCutEdge> result = new HashSet<>();
		for(GraphCutVertex source: vertices) {
			Namespace ns = source.getNamespace();
			Iterable<Namespace> namespaces = getCallingNamespaces(ns);
			Set<GraphCutVertex> callers = toVertices(namespaces, level, newVertexCache);
			for(GraphCutVertex caller: callers) {
				GraphCutEdge e = getOrCreateEdge(caller, source);
				if(!filter.test(e)) {
					continue;
				}
				result.add(e);
			}	
		}
		return result;
	}
	
	private GraphCutEdge getOrCreateEdge(GraphCutVertex start, GraphCutVertex end) {
		
		GraphCutGraph graph = graphData.getGraph();
		Iterable<GraphCutEdge> edges = graph.getEdges(start, end);
		GraphCutEdge e = CollectionUtils.any(edges);
		if(e != null) {
			return e;
		}
		return new GraphCutEdge(start, end);
	}
	
	private Set<GraphCutVertex> toStartVertices(Iterable<GraphCutEdge> edges, Predicate<GraphCutVertex> filter){
		return CollectionUtils
				.asStream(edges)
				.map(e -> e.getStart())
				.filter(filter)
				.collect(Collectors.toSet())
				;
	}
	
	private Set<GraphCutVertex> toVertices(Iterable<GraphCutEdge> edges, FcgDirection direction, Predicate<GraphCutVertex> filter){
		return direction == IN ? toStartVertices(edges, filter) : toEndVertices(edges, filter);
	}
	
	private Set<GraphCutVertex> toVertices(Iterable<Namespace> callees, GraphCutLevel level, Map<Namespace, GraphCutVertex> newVertexCache){
		return CollectionUtils.asStream(callees)
				.map(ns -> {
					if (newVertexCache.containsKey(ns)) {
						return newVertexCache.get(ns);
					}
					GraphCutVertex v = getOrCreateVertex(ns, level);
					newVertexCache.put(ns, v);
					return v;
				})
				.collect(Collectors.toSet());
	}
	
	
	private Set<GraphCutVertex> toEndVertices(Iterable<GraphCutEdge> edges, Predicate<GraphCutVertex> filter){
		return CollectionUtils
				.asStream(edges)
				.map(e -> e.getEnd())
				.filter(filter)
				.collect(Collectors.toSet());
	}
	
	private Set<GraphCutEdge> getOutgoingEdges(Iterable<GraphCutVertex> vertices, GraphCutLevel level, Predicate<GraphCutEdge> filter){
		
		Map<Namespace, GraphCutVertex> newVertexCache = new HashMap<>();
		Set<GraphCutEdge> result = new HashSet<>();
		for(GraphCutVertex source: vertices) {
			Namespace ns = source.getNamespace();
			Iterable<Namespace> namespaces = getCallerNamespaces(ns);
			Set<GraphCutVertex> callees = toVertices(namespaces, level, newVertexCache);
			for(GraphCutVertex callee: callees) {
				GraphCutEdge e = getOrCreateEdge(source, callee);
				if(!filter.test(e)) {
					continue;
				}
				result.add(e);
			}
		}
		return result;
	}
	
	private Iterable<GraphCutVertex> getVerticesAtOrGreaterThan(GraphCutLevel level){
		List<Iterable<GraphCutVertex>> result = new ArrayList<>();
		GraphCutGraph graph = graphData.getGraph();
		GraphCutLevel greatestLevel = graph.getLargestLevel(level.getDirection());
		GraphCutLevel currentLevel = level;
		while (currentLevel.getRow() <= greatestLevel.getRow()) {
			Iterable<GraphCutVertex> vertices = getVerticesByLevel(currentLevel);
			result.add(vertices);
			currentLevel = currentLevel.child();
		}
		
		Collections.reverse(result);
		
		@SuppressWarnings("unchecked")
		Iterable<GraphCutVertex>[] array = result.toArray(new Iterable[result.size()]);
		return IterableUtils.chainedIterable(array);
	}
	
	private void doExpand(GraphCutExpandingVertexCollection collection) {
		Set<GraphCutVertex> newVertices = collection.getNewVertices();
		GraphCutGraph graph = graphData.getGraph();
		for (GraphCutVertex v : newVertices) {
			graph.addVertex(v);
		}
		
		Iterable<GraphCutEdge> newEdges  = collection.getNewEdges();
		for(GraphCutEdge e : newEdges) {
			graph.addEdge(e);
		}
		
		Set<GraphCutEdge> indirectEdges = new HashSet<>();
		addEdgesToExistingVertices(newVertices, indirectEdges);
		collection.setIndirectEdges(indirectEdges);
		
		int newEdgeCount = collection.getNewEdgeCount();
		if (newEdgeCount == 0) {
			highlightExistingEdges(collection);
			return;
		}
		
		GraphViewer<GraphCutVertex, GraphCutEdge> viewer = view.getPrimaryGraphViewer();
		GraphCutLayoutExpandVerticesJob job = new GraphCutLayoutExpandVerticesJob(viewer, collection, true);
		VisualGraphViewUpdater<GraphCutVertex, GraphCutEdge> updater = view.getViewUpdater();
		updater.scheduleViewChangeJob(job);
		updateTitle();
		
		String viewName = "GraphCut Graph";
		viewer.setName(viewName);
		viewer.getAccessibleContext().setAccessibleName(viewName);
	}
	
	private void highlightExistingEdges(GraphCutExpandingVertexCollection collection) {
		
		GraphViewer<GraphCutVertex, GraphCutEdge> viewer = view.getPrimaryGraphViewer();
		VisualGraphViewUpdater<GraphCutVertex, GraphCutEdge> updater = view.getViewUpdater();
		
		Iterable<GraphCutVertex> sources = collection.getSources();
		GraphCutVertex source = CollectionUtils.any(sources);
		GraphCutLevel level = source.getLevel();
		Set<GraphCutEdge> existingEdges = getModelEdges(sources, level, unfiltered);
		GraphCutEmphasizeEdgesJob job = new GraphCutEmphasizeEdgesJob(viewer, existingEdges);
		updater.scheduleViewChangeJob(job);
	}
	
	/**
	 * Calling this method ensures that as vertices appear, edges are added
	 * @param newVertices the vertices being added to the graph 
	 * @param newEdges the set to which should be added any new edges
	 */
	private void addEdgesToExistingVertices(Iterable<GraphCutVertex> newVertices, Set<GraphCutEdge> newEdges) {
		
		GraphCutGraph graph = graphData.getGraph();
		NamespaceEdgeCache cache = graphData.getNamespaceEdgeCache();
		for(GraphCutVertex v : newVertices) {
			Namespace ns = v.getNamespace();
			Set<NamespaceEdge> edges = cache.get(ns);
			for(NamespaceEdge e : edges) {
				Namespace start = e.getStart();
				Namespace end = e.getEnd();
				GraphCutVertex v1 = graph.getVertex(start);
				GraphCutVertex v2 = graph.getVertex(end);
				
				if(v1 == null || v2 == null) {
					continue;
				}
				
				if(!graph.containsEdge(v1,v2)) {
					GraphCutEdge newEdge = new GraphCutEdge(v1,v2);
					graph.addEdge(newEdge);
					newEdges.add(newEdge);
				}
			}
		}
	}
	
	// this one uses the cache
	private Iterable<Namespace> getCallingNamespaces(Namespace ns){
		
		NamespaceEdgeCache edgeCache = graphData.getNamespaceEdgeCache();
		
		SystemUtilities.assertTrue(edgeCache.isTracked(ns), "Namespace not tracked in cache");
		
		Set<NamespaceEdge> edges = edgeCache.get(ns);
		Iterable<NamespaceEdge> filtered = 
				IterableUtils.filteredIterable(edges, e -> isCalledNamespace(ns, e));
		Iterable<Namespace> namespaces = 
				IterableUtils.transformedIterable(filtered, e -> e.getStart());
		return namespaces;
	}
	
	// this one uses the cache
	private Iterable<Namespace> getCallerNamespaces(Namespace ns){
		NamespaceEdgeCache edgeCache = graphData.getNamespaceEdgeCache();
		
		SystemUtilities.assertTrue(edgeCache.isTracked(ns), "Namespace not tracked in cache");
		
		Set<NamespaceEdge> edges = edgeCache.get(ns);
		Iterable<NamespaceEdge> filtered =
				IterableUtils.filteredIterable(edges, e -> isCallingNamespace(ns,e));
		Iterable<Namespace> namespaces = IterableUtils.transformedIterable(filtered, e -> e.getEnd());
		return namespaces;
	}
	
	private boolean isCallingNamespace(Namespace ns, NamespaceEdge e) {
		Namespace start = e.getStart();
		return start.equals(ns);
	}
	
	private boolean isCalledNamespace(Namespace ns, NamespaceEdge e) {
		Namespace end = e.getEnd();
		return end.equals(ns);
	}
	
	
	
	//============================================================================
	// Inner Classes 
	//============================================================================
	
	private class ExpansionListener implements GraphCutExpansionListener{
		
		@Override
		public void toggleIncomingVertices(GraphCutVertex v) {
			boolean expanded = v.isIncomingExpanded();
			if (expanded) {
				collapse(v, IN);
			}
			else {
				expand(v, IN);
			}
		}
		
		@Override
		public void toggleOutgoingVertices(GraphCutVertex v) {
			boolean expanded = v.isOutgoingExpanded();
			if (expanded) {
				collapse(v, OUT);
			}
			else {
				expand(v, OUT);
			}
		}
	}
	
	private abstract class AbstractCollapseAction extends DockingAction{
		protected FcgDirection direction;
		
		AbstractCollapseAction(String actionName, FcgDirection direction){
			super(actionName, plugin.getName());
			this.direction = direction;
			
			setPopupMenuData(new MenuData(new String[] {actionName}, MENU_GROUP_EXPAND));
			setHelpLocation(new HelpLocation("GraphCutPlugin", "Expand_Collapse"));
		}
		
		abstract void collapseFromContext(VgVertexContext<GraphCutVertex> context);
		
		@Override
		public void actionPerformed(ActionContext context) {
			VgVertexContext<GraphCutVertex> vContext = getVertexContext(context);
			collapseFromContext(vContext);
		}
		
		@Override
		public boolean isEnabledForContext(ActionContext context) {
			VgVertexContext<GraphCutVertex> vContext = getVertexContext(context);
			if(vContext ==  null) {
				return false;
			}
			
			GraphCutVertex v = vContext.getVertex();
			boolean expanded = direction == IN ? v.isIncomingExpanded() : v.isOutgoingExpanded();
			if(!expanded) {
				return false;
			}
			
			if(!isMyDirection(v.getLevel())) {
				return false;
			}
			
			return true;
		}
		
		boolean isMyDirection(GraphCutLevel level) {
			return level.getDirection() == direction;
		}
		
	}
	
	private class CollapseAction extends AbstractCollapseAction {
		
		CollapseAction(String actionName, FcgDirection direction){
			super(actionName, direction);
		}
		
		@Override
		void collapseFromContext(VgVertexContext<GraphCutVertex> context) {
			GraphCutVertex v = context.getVertex();
			GraphCutLevel level = v.getLevel();
			collapseLevel(level, direction);
		}
		
		@Override
		boolean isMyDirection(GraphCutLevel level) {
			if (level.getDirection() == FcgDirection.IN_AND_OUT) {
				return true;
			}
			return level.getDirection() == direction;
		}
	}
	
	private class CollapseLevelAction extends AbstractCollapseAction {
		
		CollapseLevelAction(String actionName, FcgDirection direction){
			super(actionName, direction);
		}
		
		@Override
		void collapseFromContext(VgVertexContext<GraphCutVertex> context) {
			GraphCutVertex v = context.getVertex();
			GraphCutLevel level = v.getLevel();
			collapseLevel(level, direction);
		}
		
		@Override
		boolean isMyDirection(GraphCutLevel level) {
			if (level.getDirection() == FcgDirection.IN_AND_OUT) {
				return true;
			}
			return level.getDirection() == direction;
		}
	}
	
	private abstract class AbstractExpandAction extends DockingAction {
		protected FcgDirection direction;
		
		AbstractExpandAction(String actionName, FcgDirection direction){
			super(actionName, plugin.getName());
			this.direction = direction;
			
			setPopupMenuData(new MenuData(new String[] {actionName}, MENU_GROUP_EXPAND));
			setHelpLocation(new HelpLocation("GraphCutPlugin", "Expand_Collapse"));
		}
		
		abstract void expandFromContext(VgVertexContext<GraphCutVertex> context);
		
		abstract boolean isExpandable(GraphCutVertex v);
		
		@Override
		public void actionPerformed(ActionContext context) {
			VgVertexContext<GraphCutVertex> vContext = getVertexContext(context);
			expandFromContext(vContext);
		}
			
		@Override
		public boolean isEnabledForContext(ActionContext context) {
			VgVertexContext<GraphCutVertex> vContext = getVertexContext(context);
			if(vContext == null) {
				return false;
			}
			
			GraphCutVertex v = vContext.getVertex();
			boolean isExpandable = isExpandable(v);
			if(!isExpandable) {
				return false;
			}
			
			if(!isMyDirection(v.getLevel())) {
				return false;
			}
			
			return true;
		}
		
		boolean isMyDirection(GraphCutLevel level) {
			return level.getDirection() == direction;
		}
	}
	
	private class ExpandAction extends AbstractExpandAction {
		
		ExpandAction(String actionName, FcgDirection direction){
			super(actionName, direction);
		}
		
		@Override
		void expandFromContext(VgVertexContext<GraphCutVertex> context) {
			GraphCutVertex v = context.getVertex();
			expand(v, direction);
		}
		
		@Override
		boolean isExpandable(GraphCutVertex v) {
			return v.canExpand();
		}
	}
	
	private class ExpandLevelAction extends AbstractExpandAction {
		ExpandLevelAction(String actionName, FcgDirection direction){
			super(actionName, direction);
		}
		
		@Override 
		void expandFromContext(VgVertexContext<GraphCutVertex> context) {
			GraphCutVertex v = context.getVertex();
			GraphCutLevel level = v.getLevel();
			Iterable<GraphCutVertex> vertices = getVerticesByLevel(v.getLevel());
			expand(vertices, level, direction);
		}
		
		@Override
		boolean isMyDirection(GraphCutLevel level) {
			if(level.getDirection() == FcgDirection.IN_AND_OUT) {
				return true;
			}
			return level.getDirection() == direction;
		}
		
		@Override
		boolean isExpandable(GraphCutVertex vertex) {
			Iterable<GraphCutVertex> vertices = getVerticesByLevel(vertex.getLevel());
			if (direction == IN) {
				return CollectionUtils.asStream(vertices)
						.anyMatch(GraphCutVertex::canExpandIncomingReferences);
			}
			return CollectionUtils.asStream(vertices)
					.anyMatch(GraphCutVertex::canExpandOutgoingReferences);
		}
	}
	
	public void addToWhitelist(Namespace ns) {
		FilterWhitelist.add(ns);
		rebuildCurrentGraph();
	}
	
	public Set<Namespace> getNamespacesInFilter() {
		return FilterWhitelist;
	}
	
	public void removeFromWhitelist(Namespace ns) {
		FilterWhitelist.remove(ns);
		rebuildCurrentGraph();
	}
	
	public void resetWhitelist() {
		FilterWhitelist.clear();
		rebuildCurrentGraph();
	}
}
