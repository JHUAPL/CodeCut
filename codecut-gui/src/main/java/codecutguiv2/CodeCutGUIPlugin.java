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


package codecutguiv2;

import java.awt.Cursor;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Iterator;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.awt.event.KeyEvent;
import java.io.*;

import javax.swing.ImageIcon;
import javax.swing.Icon;

import docking.ActionContext;
import docking.action.*;
import docking.tool.ToolConstants;
import docking.widgets.OptionDialog;
import docking.widgets.filechooser.GhidraFileChooser;
import functioncalls.plugin.FcgProvider;
import ghidra.app.CorePluginPackage;
import ghidra.app.context.ProgramActionContext;
import ghidra.app.context.ProgramContextAction;
import ghidra.app.decompiler.component.DecompilerController;
import ghidra.app.events.ProgramActivatedPluginEvent;
import ghidra.app.events.ProgramLocationPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.decompile.DecompilerProvider;
import ghidra.app.plugin.core.symboltree.actions.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraState;
import ghidra.app.services.BlockModelService;
import ghidra.app.services.GoToService;
//import ghidra.app.services.DecExtendService;
import ghidra.app.util.SymbolInspector;
import ghidra.framework.model.*;
import ghidra.framework.options.Options;
import ghidra.framework.options.OptionsChangeListener;
import ghidra.framework.options.SaveState;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.framework.preferences.Preferences;
import ghidra.graph.viewer.options.VisualGraphOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ChangeManager;
import ghidra.program.util.DefinedDataIterator;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.program.util.ProgramChangeRecord;
import ghidra.program.util.ProgramLocation;
import ghidra.jython.GhidraJythonInterpreter;
import ghidra.jython.JythonScript;
import ghidra.util.HTMLUtilities;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.Swing;
import ghidra.util.SystemUtilities;
import ghidra.util.bean.opteditor.OptionsVetoException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.table.GhidraTable;
import ghidra.util.task.SwingUpdateManager;
import graphcut.*;
import ghidra.util.task.*;
import ghidra.util.datastruct.*;
import resources.Icons;
import resources.ResourceManager;
import static ghidra.program.util.ProgramEvent.*;


/**
 * Plugin to display the symbol table for a program.
 * Allows navigation and changing the symbol name.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.UNSTABLE,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "Show Symbols in Symbol Table",
	description = "This plugin shows the symbols in the symbol table," +
			" provides navigation to the symbols in the Code Browser, and " +
			"allows symbols to be renamed and deleted. This plugin also " +
			"shows references to a symbol. Filters can be set " +
			"to show subsets of the symbols." +
			" Allows the graphing of namespaces and their relations.",
	servicesRequired = { GoToService.class, BlockModelService.class },
	eventsProduced = { ProgramLocationPluginEvent.class },
	eventsConsumed = { ProgramActivatedPluginEvent.class }
)
//@formatter:on
public class CodeCutGUIPlugin extends ProgramPlugin implements DomainObjectListener, OptionsChangeListener{

	final static Cursor WAIT_CURSOR = new Cursor(Cursor.WAIT_CURSOR);
	final static Cursor NORM_CURSOR = new Cursor(Cursor.DEFAULT_CURSOR);

	private final static String OPTION_NAME_PYTHON_EXEC = "Python Executable";
	private final static String OPTION_DEFAULT_PYTHON_EXEC = "/usr/bin/python3";
	private String pythonExec = OPTION_DEFAULT_PYTHON_EXEC;
	
	private DockingAction openRefsAction;
	private DockingAction deleteAction;
	private DockingAction setFilterAction;
	private DockingAction renameNamespaceAction;
	private DockingAction createNamespaceAction;
	private DockingAction combineNamespaceAction;
	private ToggleDockingAction referencesToAction;
	private ToggleDockingAction instructionsFromAction;
	private ToggleDockingAction dataFromAction;
	private ToggleDockingAction selectionNavigationAction; 

	private SymbolProvider symProvider;
	private ReferenceProvider refProvider;
	private RenameProvider renameProvider;
	private CreateProvider createProvider;
	private CombineProvider combineProvider;
	private SymbolInspector inspector;
	private Program currentProgram;
	private GoToService gotoService;
	private BlockModelService blockModelService;
	private SwingUpdateManager swingMgr;
	private DecompileRangeProvider decompProvider; 
	
	private Map<Namespace, List<String>> stringMap;
	private Map<Namespace, String> suggestedModuleNames;
	//private DecExtendService decExtService; 
	
	//GraphCut Variables
	public static final String GRAPH_NAME = "CodeCut Object Graph";
	static final String SHOW_PROVIDER_ACTION_NAME = "Display CodeCut Object Graph";
	public static final HelpLocation DEFAULT_HELP = 
			new HelpLocation(CodeCutGUIPlugin.class.getSimpleName(),
					CodeCutGUIPlugin.class.getSimpleName());
	private GraphCutProvider graphProvider;
	private VisualGraphOptions vgOptions = new VisualGraphOptions();
	private static final int MIN_UPDATE_DELAY = 750;
	private SwingUpdateManager locationUpdater = new SwingUpdateManager(MIN_UPDATE_DELAY, () ->{
		doLocationChanged();
	});
	private ChecklistProvider checklistProvider;
	
	public CodeCutGUIPlugin(PluginTool tool) {
		super(tool);

		ToolOptions options = tool.getOptions(OPTION_NAME_PYTHON_EXEC);
		options.setString(OPTION_NAME_PYTHON_EXEC, OPTION_DEFAULT_PYTHON_EXEC);
		
		swingMgr = new SwingUpdateManager(1000, () -> {
			symProvider.getComponent().repaint();
			refProvider.getComponent().repaint();
		});
		stringMap = new HashMap<>();
		suggestedModuleNames = new HashMap<>();
	}


	@Override
	protected void init() {
		gotoService = tool.getService(GoToService.class);
		blockModelService = tool.getService(BlockModelService.class);

		symProvider = new SymbolProvider(this);
		refProvider = new ReferenceProvider(this);
		renameProvider = new RenameProvider(this);
		createProvider = new CreateProvider(this);
		combineProvider = new CombineProvider(this);
		decompProvider = new DecompileRangeProvider(this);
		graphProvider = new GraphCutProvider(tool, this);
		checklistProvider = new ChecklistProvider(this);
		
		createNamespaceActions();
		createSymActions();
		createRefActions();
		createMapActions();
		createExportActions(); 
		createGraphActions();
		initializeGraphOptions();
		createChecklistActions();
		
		//decExtService = tool.getService(DecExtendService.class);
		//if (decExtService == null) {
		//	Msg.info(new Object(),  "ERROR: Decompiler Extension is not installed");
		//}
		
		inspector = new SymbolInspector(getTool(), symProvider.getComponent());
	}

	
	
	
	/**
	 * Tells a plugin that it is no longer needed.
	 * The plugin should remove itself from anything that
	 * it is registered to and release any resources.
	 */
	@Override
	public void dispose() {
		super.dispose();
		swingMgr.dispose();

		deleteAction.dispose();
		renameNamespaceAction.dispose();

		if (symProvider != null) {
			symProvider.dispose();
			symProvider = null;
		}
		if (refProvider != null) {
			refProvider.dispose();
			refProvider = null;
		}
		if (renameProvider != null) {
			renameProvider.dispose();
			renameProvider = null;
		}
		if (createProvider != null) {
			createProvider.dispose();
			createProvider = null;
		}
		if (combineProvider != null) {
			combineProvider.dispose();
			combineProvider = null;
		}
		if (currentProgram != null) {
			currentProgram.removeListener(this);
			currentProgram = null;
		}
		gotoService = null;
		blockModelService = null;
		//decExtService = null;

		if (inspector != null) {
			inspector.dispose();
			inspector = null;
		}
		
		if (stringMap != null) {
			stringMap.clear();
			stringMap = null;
		}
		
		if (suggestedModuleNames != null) {
			suggestedModuleNames.clear();
			suggestedModuleNames = null;
		}
		
		graphProvider.dispose();
		checklistProvider.dispose();
		
	}

	@Override
	public void readConfigState(SaveState saveState) {
		symProvider.readConfigState(saveState);
		graphProvider.readConfigState(saveState);
	}

	@Override
	public void writeConfigState(SaveState saveState) {
		symProvider.writeConfigState(saveState);
		graphProvider.writeConfigState(saveState);
	}

	@Override
	public void processEvent(PluginEvent event) {
		super.processEvent(event);
		if (event instanceof ProgramActivatedPluginEvent) {
			ProgramActivatedPluginEvent progEvent = (ProgramActivatedPluginEvent) event;
			Program oldProg = currentProgram;
			Program newProg = progEvent.getActiveProgram();

			if (oldProg != null) {
				inspector.setProgram(null);
				oldProg.removeListener(this);
				symProvider.setProgram(null, inspector);
				refProvider.setProgram(null, inspector);
				tool.contextChanged(symProvider);
			}
			currentProgram = newProg;
			if (newProg != null) {

				currentProgram.addListener(this);

				inspector.setProgram(currentProgram);

				symProvider.setProgram(currentProgram, inspector);
				refProvider.setProgram(currentProgram, inspector);
			}

			tool.contextChanged(symProvider);
		}
	}

	@Override
	public void domainObjectChanged(DomainObjectChangedEvent ev) {
		if (!symProvider.isVisible()) {
			return;
		}
		
		if (CodecutUtils.nsUpdating()) {
			return;
		}
		
		if (ev.containsEvent(DomainObject.DO_OBJECT_RESTORED) ||
			ev.containsEvent(ChangeManager.DOCR_MEMORY_BLOCK_ADDED) ||
			ev.containsEvent(ChangeManager.DOCR_MEMORY_BLOCK_REMOVED)) {

			symProvider.reload();
			refProvider.reload();
			return;
		}

		int eventCnt = ev.numRecords();
		for (int i = 0; i < eventCnt; ++i) {
			DomainObjectChangeRecord doRecord = ev.getChangeRecord(i);

			int eventType = doRecord.getEventType().getId();
			if (!(doRecord instanceof ProgramChangeRecord)) {
				continue;
			}

			ProgramChangeRecord rec = (ProgramChangeRecord) doRecord;
			Symbol symbol = null;
			SymbolTable symbolTable = currentProgram.getSymbolTable();
			
			if(eventType == CODE_ADDED.getId() || eventType == CODE_REMOVED.getId()) {
				if (rec.getNewValue() instanceof Data) {
					symbol = symbolTable.getPrimarySymbol(rec.getStart());
					if (symbol != null && symbol.isDynamic()) {
						symProvider.symbolChanged(symbol);
						refProvider.symbolChanged(symbol);
					}
				}
			}
			
			else if(eventType == SYMBOL_ADDED.getId()) {
				Address addAddr = rec.getStart();
				Symbol primaryAtAdd = symbolTable.getPrimarySymbol(addAddr);
				if (primaryAtAdd != null && primaryAtAdd.isDynamic()) {
					symProvider.symbolRemoved(primaryAtAdd);
				}
				symbol = (Symbol) rec.getNewValue();
				symProvider.symbolAdded(symbol);
				refProvider.symbolAdded(symbol);
			}
			
			else if(eventType == SYMBOL_REMOVED.getId()) {
				Address removeAddr = rec.getStart();
				Long symbolID = (Long) rec.getNewValue();
				Symbol removedSymbol;
				removedSymbol = new SymbolPlaceholder(symbolID, removeAddr, getProgram());
				symProvider.symbolRemoved(removedSymbol);
				refProvider.symbolRemoved(removedSymbol);
				Symbol primaryAtRemove = symbolTable.getPrimarySymbol(removeAddr);
				if (primaryAtRemove != null && primaryAtRemove.isDynamic()) {
					symProvider.symbolAdded(primaryAtRemove);
					refProvider.symbolRemoved(primaryAtRemove);
				}
			}
			
			else if((eventType == SYMBOL_RENAMED.getId())
						|| (eventType == SYMBOL_SCOPE_CHANGED.getId())
						|| (eventType == SYMBOL_DATA_CHANGED.getId())) {
				
				symbol = (Symbol) rec.getObject();
				if (!CodecutUtils.nsUpdating()) {
					if (!symbol.isDeleted()) {
						symProvider.symbolChanged(symbol);
						refProvider.symbolChanged(symbol);
					}
				}
			}
			
			else if(eventType == SYMBOL_SOURCE_CHANGED.getId()) {
				symbol = (Symbol) rec.getObject();
				symProvider.symbolChanged(symbol);
			}
			
			else if(eventType == SYMBOL_PRIMARY_STATE_CHANGED.getId()) {
				symbol = (Symbol) rec.getNewValue();
				symProvider.symbolChanged(symbol);
				Symbol oldSymbol = (Symbol) rec.getOldValue();
				if (oldSymbol != null) {
					symProvider.symbolChanged(oldSymbol);
				}
			}
			
			else if(eventType == REFERENCE_ADDED.getId()) {
				Reference ref = (Reference) rec.getObject();
				symbol = symbolTable.getSymbol(ref);
				if (symbol != null) {
					symProvider.symbolChanged(symbol);
					refProvider.symbolChanged(symbol);
				}
			}
			
			else if(eventType == REFERENCE_REMOVED.getId()) {
				Reference ref = (Reference) rec.getObject();
				Address toAddr = ref.getToAddress();
				if (toAddr.isMemoryAddress()) {
					symbol = symbolTable.getSymbol(ref);
					if (symbol == null) {
						
						Symbol removedSymbol;
						long id = symbolTable.getDynamicSymbolID(ref.getToAddress());
						removedSymbol = new SymbolPlaceholder(id, toAddr, getProgram());
						symProvider.symbolRemoved(removedSymbol);
					}
					else {
						refProvider.symbolChanged(symbol);
					}
				}
			}
			
			else if(eventType == EXTERNAL_ENTRY_ADDED.getId() || eventType == EXTERNAL_ENTRY_REMOVED.getId()) {
				Symbol[] symbols = symbolTable.getSymbols(rec.getStart());
				for (Symbol element : symbols) {
					symProvider.symbolChanged(element);
					refProvider.symbolChanged(element);
				}
			}
			
		}
		
	}

	Program getProgram() {
		return currentProgram;
	}

	BlockModelService getBlockModelService() {
		return blockModelService;
	}

	GoToService getGoToService() {
		return gotoService;
	}

	SymbolProvider getSymbolProvider() {
		return symProvider;
	}
	
	GraphCutProvider getGraphProvider() {
		return graphProvider;
	}

	ReferenceProvider getReferenceProvider() {
		return refProvider;
	}

	void openSymbolProvider() {
		if (symProvider != null) {
			symProvider.open();
		}
	}

	void closeReferenceProvider() {
		if (refProvider != null) {
			refProvider.closeComponent();
		}
	}

	void createNamespaceActions () {
		String popupGroup = "1"; 
		
		renameNamespaceAction = new DockingAction("Rename Namespace", getName(), KeyBindingType.SHARED) {
			@Override
			public void actionPerformed(ActionContext context) {
				renameProvider.setCurrentNamespace(symProvider.getCurrentSymbol().getParentNamespace());
				renameProvider.open();
			}
			
			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return symProvider.getCurrentSymbol() != null;
			}
		};
		renameNamespaceAction.setPopupMenuData(
				new MenuData(new String[] { "Rename Namespace" }, popupGroup));
		renameNamespaceAction.setDescription("Rename Namespace");
		tool.addLocalAction(symProvider, renameNamespaceAction);
		
		createNamespaceAction = new DockingAction("Split Namespace Here", getName(), KeyBindingType.SHARED) {
			@Override 
			public void actionPerformed(ActionContext context) {
				createProvider.setCurrentNamespace(symProvider.getCurrentSymbol().getParentNamespace());
				createProvider.setCurrentSymbol(symProvider.getCurrentSymbol());
				createProvider.open();
			}
			
			@Override 
			public boolean isEnabledForContext(ActionContext context) {
				return symProvider.getCurrentSymbol() != null;
			}
		};
		createNamespaceAction.setPopupMenuData(
				new MenuData(new String[] { "Split Namespace Here" }, popupGroup));
		createNamespaceAction.setDescription("Split namespace at this symbol");
		tool.addLocalAction(symProvider, createNamespaceAction);
		
		combineNamespaceAction = new DockingAction("Combine Namespaces", getName(), KeyBindingType.SHARED) {
			@Override 
			public void actionPerformed(ActionContext context) {
				combineProvider.setFirstNamespace(symProvider.getCurrentSymbol().getParentNamespace());
				combineProvider.open();
			}
			
			@Override 
			public boolean isEnabledForContext(ActionContext context) {
				return symProvider.getCurrentSymbol() != null;
			}
		};
		combineNamespaceAction.setPopupMenuData(
				new MenuData(new String[] { "Combine Namespaces" }, popupGroup));
		combineNamespaceAction.setDescription("Combine another namespace with selected namespace");
		tool.addLocalAction(symProvider, combineNamespaceAction);
		
	}
	
	private void createSymActions() {
		String popupGroup = "1";

		openRefsAction = new DockingAction("Symbol References", getName(), KeyBindingType.SHARED) {
			@Override
			public void actionPerformed(ActionContext context) {
				refProvider.open();
				refProvider.setCurrentSymbol(symProvider.getCurrentSymbol());
			}
			
			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return symProvider.getCurrentSymbol() != null;
			}
		};
		Icon icon = ResourceManager.loadImage("images/table_go.png");
		openRefsAction.setPopupMenuData(
			new MenuData(new String[] { "Symbol References" }, icon, popupGroup));
		openRefsAction.setToolBarData(new ToolBarData(icon));

		openRefsAction.setDescription("Display Symbol References");
		tool.addLocalAction(symProvider, openRefsAction);

		deleteAction = new DockingAction("Delete Symbols", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				symProvider.deleteSymbols();
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return symProvider.getCurrentSymbol() != null;
			}

			@Override
			public boolean isAddToPopup(ActionContext context) {
				return true;
			}
		};

		icon = ResourceManager.loadImage("images/edit-delete.png");
		String deleteGroup = "3"; // put in a group after the others
		deleteAction.setPopupMenuData(new MenuData(new String[] { "Delete" }, icon, deleteGroup));
		deleteAction.setToolBarData(new ToolBarData(icon));
		deleteAction.setKeyBindingData(new KeyBindingData(KeyEvent.VK_DELETE, 0));

		deleteAction.setDescription("Delete Selected Symbols");
		deleteAction.setEnabled(false);
		tool.addLocalAction(symProvider, deleteAction);

		DockingAction editExternalLocationAction = new EditExternalLocationAction(this);
		tool.addLocalAction(symProvider, editExternalLocationAction);

		setFilterAction = new DockingAction("Set Filter", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				symProvider.setFilter();
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return currentProgram != null;
			}
		};
		icon = Icons.CONFIGURE_FILTER_ICON;
		setFilterAction.setToolBarData(new ToolBarData(icon));

		setFilterAction.setDescription("Configure Symbol Filter");
		tool.addLocalAction(symProvider, setFilterAction);

		// override the SelectionNavigationAction to handle both tables that this plugin uses
		selectionNavigationAction = new ToggleDockingAction("Set Navigation", getName()) {
			private boolean selected = false; 
			@Override
			public void actionPerformed(ActionContext context) {
				selected = !selected; 
				setSelected(selected);
				List<GhidraTable> tableList = symProvider.getAllTables();
				Iterator<GhidraTable> it = tableList.iterator();
				while (it.hasNext()) {
					GhidraTable t = it.next();
					t.setNavigateOnSelectionEnabled(selected);
				}
			}
		};
		icon = Icons.NAVIGATE_ON_INCOMING_EVENT_ICON;
		selectionNavigationAction.setToolBarData(new ToolBarData(icon));
		selectionNavigationAction.setDescription(HTMLUtilities.toHTML("Toggle <b>on</b> means to navigate to the location\n" +
				"in the program that corresponds to the selected row,\n as the selection changes."));
		selectionNavigationAction.setSelected(true);
		tool.addLocalAction(symProvider, selectionNavigationAction);
		
		
		String pinnedPopupGroup = "2"; // second group
		DockingAction setPinnedAction = new PinSymbolAction(getName(), pinnedPopupGroup);
		tool.addAction(setPinnedAction);

		DockingAction clearPinnedAction = new ClearPinSymbolAction(getName(), pinnedPopupGroup);
		tool.addAction(clearPinnedAction);
	}

	private void createRefActions() {
		referencesToAction = new ToggleDockingAction("References To", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				if (referencesToAction.isSelected()) {
					refProvider.showReferencesTo();
					referencesToAction.setSelected(true);
					instructionsFromAction.setSelected(false);
					dataFromAction.setSelected(false);
				}
				// don't let the user de-click the button, since these buttons change in
				// response to each other, like a javax.swing.ButtonGroup set
				else {
					reselectAction(referencesToAction);
				}
			}
		};
		referencesToAction.setDescription("References To");
		referencesToAction.setSelected(true);
		referencesToAction.setToolBarData(
			new ToolBarData(ResourceManager.loadImage("images/references_to.gif"), null));

		tool.addLocalAction(refProvider, referencesToAction);

		instructionsFromAction = new ToggleDockingAction("Instruction References From", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				if (instructionsFromAction.isSelected()) {
					refProvider.showInstructionsFrom();
					referencesToAction.setSelected(false);
					instructionsFromAction.setSelected(true);
					dataFromAction.setSelected(false);
				}
				// don't let the user de-click the button, since these buttons change in
				// response to each other, like a javax.swing.ButtonGroup set
				else {
					reselectAction(instructionsFromAction);
				}
			}
		};
		instructionsFromAction.setDescription("Instructions From");
		instructionsFromAction.setSelected(false);
		instructionsFromAction.setToolBarData(
			new ToolBarData(ResourceManager.loadImage("images/I.gif"), null));

		tool.addLocalAction(refProvider, instructionsFromAction);

		dataFromAction = new ToggleDockingAction("Data References From", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				if (dataFromAction.isSelected()) {
					refProvider.showDataFrom();
					referencesToAction.setSelected(false);
					instructionsFromAction.setSelected(false);
					dataFromAction.setSelected(true);
				}
				// don't let the user de-click the button, since these buttons change in
				// response to each other, like a javax.swing.ButtonGroup set
				else {
					reselectAction(dataFromAction);
				}
			}
		};
		dataFromAction.setDescription("Data From");
		dataFromAction.setSelected(false);
		dataFromAction.setToolBarData(
			new ToolBarData(ResourceManager.loadImage("images/D.gif"), null));

		tool.addLocalAction(refProvider, dataFromAction);
	}

	private void createMapActions() {
		ProgramContextAction exportMapAction = 
				new ProgramContextAction("Export_Module_Map", this.getName()) {
			@Override 
			public boolean isEnabledForContext(ProgramActionContext context) {
				return context.getProgram() != null;
			}
			@Override
			protected void actionPerformed(ProgramActionContext programContext) {
				exportModuleMap(); 
			}
			
		};
		
		MenuData menuData = new MenuData(new String[] {ToolConstants.MENU_FILE, "Export Module Map..." }, null, "Module Map");
		menuData.setMenuSubGroup("1");
		exportMapAction.setMenuBarData(menuData);
		exportMapAction.setHelpLocation(new HelpLocation("Map", exportMapAction.getName()));
		exportMapAction.setAddToAllWindows(true);
		tool.addAction(exportMapAction);
		
		
		ProgramContextAction importMapAction = 
				new ProgramContextAction("Import_Module_Map", this.getName()) {
			@Override 
			public boolean isEnabledForContext(ProgramActionContext context) {
				return context.getProgram() != null;
			}
			
			@Override
			protected void actionPerformed(ProgramActionContext programContext) {
				importModuleMap();
			}
		};
		MenuData importMenuData = new MenuData(new String[] {ToolConstants.MENU_FILE, "Import Module Map..."}, null, "Module Map");
		importMenuData.setMenuSubGroup("1");
		importMapAction.setMenuBarData(importMenuData);
		importMapAction.setHelpLocation(new HelpLocation("Map", importMapAction.getName()));		
		importMapAction.setAddToAllWindows(true);		
		tool.addAction(importMapAction);
		

		ProgramContextAction moduleNameGuessingAction = 
				new ProgramContextAction("Module_Name_Guessing", this.getName()) {
			@Override 
			public boolean isEnabledForContext(ProgramActionContext context) {
				return context.getProgram() != null;
			}
			
			@Override 
			protected void actionPerformed(ProgramActionContext programContext) {
				getModuleStrings();
				ToolOptions options = CodeCutGUIPlugin.this.tool.getOptions(OPTION_NAME_PYTHON_EXEC);
				CodeCutGUIPlugin.this.pythonExec = options.getString(OPTION_NAME_PYTHON_EXEC, CodeCutGUIPlugin.this.pythonExec);
				if (stringMap != null) {
					guessModuleNames();
				}
				symProvider.reload();
			}
		};
		MenuData guessModule = new MenuData(new String[] {ToolConstants.MENU_ANALYSIS, "Guess Module Names"}, null, "Guess Module Names");
		guessModule.setMenuSubGroup("1");
		moduleNameGuessingAction.setMenuBarData(guessModule);
		moduleNameGuessingAction.setHelpLocation(new HelpLocation("Map", moduleNameGuessingAction.getName()));
		moduleNameGuessingAction.setAddToAllWindows(true);
		tool.addAction(moduleNameGuessingAction);
		
		
	}
	
	private void createExportActions() {
//Need Decompiler extensions		
		/*
		DockingAction exportDwarf = 
				new DockingAction("export_dwarf", this.getName()) {
			@Override 
			public boolean isEnabledForContext(ActionContext context) {
				return symProvider.getCurrentSymbol() != null;
			}
			@Override
			public void actionPerformed(ActionContext programContext) {
				if (decExtService == null) {
					Msg.info(new Object(),  "Cannot export DWARF without decompiler extension service");
					return;
				}
				if (decExtService.getMapping() != null) {
					decExtService.exportDWARF(symProvider.getCurrentSymbol().getParentNamespace().getName());
				}
			}
			
		};
		
		MenuData menuData = new MenuData(new String[] {"Export", "Export to C/ELF with DWARF" }, null, "Export");
		menuData.setMenuSubGroup("1");
		exportDwarf.setPopupMenuData(menuData);
		//exportDwarf.setAddToAllWindows(true);
		tool.addLocalAction(symProvider, exportDwarf);
		*/
		
		DockingAction exportC = 
				new DockingAction("export_c", this.getName()) {
			@Override 
			public boolean isEnabledForContext(ActionContext context) {
				return symProvider.getCurrentSymbol() != null;
			}
			@Override
			public void actionPerformed(ActionContext context) {
				decompProvider.setFunc(symProvider.getCurrentSymbol().getAddress());
				decompProvider.open(); 
			}
			
		};
		
		MenuData menuData = new MenuData(new String[] {"Export", "Select range to export to recomp. C (EXPERIMENTAL)" }, null, "Export");
		menuData.setMenuSubGroup("1");
		exportC.setPopupMenuData(menuData);
		//exportC.setAddToAllWindows(true);
		tool.addLocalAction(symProvider, exportC);
		
		DockingAction exportCModule = 
				new DockingAction("export_c_mod", this.getName()) {
			@Override 
			public boolean isEnabledForContext(ActionContext context) {
				return symProvider.getCurrentSymbol() != null;
			}
			@Override
			public void actionPerformed(ActionContext context) {
				AddressRange theRange = CodecutUtils.getNamespaceRange(getProgram(), getSymbolProvider().getCurrentSymbol());
				exportC(theRange.getMinAddress().toString(), theRange.getMaxAddress().toString());
			}
			
		};
		
		menuData = new MenuData(new String[] {"Export", "Export module to recomp. C (EXPERIMENTAL)" }, null, "Export");
		menuData.setMenuSubGroup("1");
		exportCModule.setPopupMenuData(menuData);
		//exportC.setAddToAllWindows(true);
		tool.addLocalAction(symProvider, exportCModule);

//Need to get obj file output script to work without the parent ELF
//Could check and only enable this if the loaded file was an ARM ELF
/*
		DockingAction exportElf = 
				new DockingAction("export_elf", this.getName()) {
			@Override 
			public boolean isEnabledForContext(ActionContext context) {
				return symProvider.getCurrentSymbol() != null;
			}
			@Override
			public void actionPerformed(ActionContext programContext) {
				Namespace ns = symProvider.getCurrentSymbol().getParentNamespace(); // for .o output
				Msg.info(new Object(), ns.getName());
				GhidraState gstate = new GhidraState(tool, tool.getProject(), currentProgram, null, null, null);
				OFileExporter outputELF = new OFileExporter(gstate, ns.getName());
				try {
					outputELF.run();
				} catch (Exception e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} 
			}
			
		};
		
		menuData = new MenuData(new String[] {"Export", "Export to ELF (EXPERIMENTAL)" }, null, "Export");
		menuData.setMenuSubGroup("1");
		exportElf.setPopupMenuData(menuData);
		//exportElf.setAddToAllWindows(true);
		tool.addLocalAction(symProvider, exportElf);
*/
//Need Decompiler Extensions
/*
		DockingAction updateMapping = new DockingAction("Update Decompiler Mapping", getName()) {
			@Override 
			public void actionPerformed(ActionContext context) {
				gotoService.goTo(symProvider.getCurrentSymbol().getProgramLocation());
				if (decExtService == null) { 
					Msg.info(new Object(),  "Cannot update mapping without decompiler extension services");
					return; 
				}
				Set<String> funcs = decExtService.updatedFuncs();
				if (funcs != null && funcs.contains(symProvider.getCurrentSymbol().getName())) {
					decExtService.getMapByFuncName(symProvider.getCurrentSymbol().getName());
					Msg.info(new Object(), "UPDATED MAPPING EXISTS FOR: " + symProvider.getCurrentSymbol().getName());
				}
				else {
					// Reset decompiler process 
					DecompilerController decompileController = ((DecompilerProvider)tool.getComponentProvider("Decompiler")).getController();
					decompileController.resetDecompiler();
					try {
						decExtService.updateMapping();
					} catch (Exception e) {
						e.printStackTrace();
					}
				}
				
			}
			
			@Override 
			public boolean isEnabledForContext(ActionContext context) {
				return symProvider.getCurrentSymbol() != null;
			}
		};
		updateMapping.setPopupMenuData(
				new MenuData(new String[] { "Update Decompiler Mapping" }, "2"));
		tool.addLocalAction(symProvider, updateMapping);
*/

	}


	private void guessModuleNames() {
		Task guessNamesTask = new Task("Guess Module Names", true, true, true) {
			@Override 
			public void run(TaskMonitor monitor) {
				monitor.setMessage("Gathering string information...");
				long startCount = stringMap.size();
				long numRemaining = stringMap.size();
				monitor.initialize(startCount);
				
				// Force the updating state so the CodeCut GUI does not attempt to refresh
				// until after all updates are complete (makes things MUCH faster).
				CodecutUtils.setUpdating(true);
				
				try {
					for (Map.Entry<Namespace, List<String>> entry : stringMap.entrySet()) {		
						
						if (!monitor.isCancelled()) {
							ModNamingPython modNamer = new ModNamingPython(pythonExec);
							Namespace ns = entry.getKey();
							
							if (!ns.getName().equals("Global")) {
								List<String> strList = entry.getValue();
								monitor.setMessage("Guessing module name for " + ns.getName());
								
								String sep = "tzvlw"; // separator used by modnaming.py
														
								String allStrings = String.join(" " + sep + " ", strList);
								
								allStrings = allStrings.replaceAll("%[0-9A-Za-z]+"," ");
								allStrings = allStrings.replaceAll("-","_");
								allStrings = allStrings.replaceAll("_"," ");
								allStrings = allStrings.replaceAll("[/\\\\]"," ");
								allStrings = allStrings.replaceAll("[^A-Za-z0-9_.]"," ");
								allStrings = allStrings.concat("\r\n\0");
	
								int success = modNamer.startProcess();
								if (success == -1) {
									return;
								}
					
								String error = modNamer.readProcessError();
								if (!error.isEmpty()) {
									Msg.error(this, "Error starting module name guessing script: " + error);
									break;
								}
								
								modNamer.writeProcess(allStrings);
								
								modNamer.waitFor();
								
								error = modNamer.readProcessError();
								if (!error.isEmpty()) {
									Msg.error(this, "Error providing strings to module name guessing script " + error);
									break;
								}
								
								String suggestedName = modNamer.readProcessOutput();
								//if name is "unknown" (e.g. modnaming found no repeated strings) don't bother renaming 
								if (suggestedName.equals("unknown")) {
									Msg.info(this, "No name guess found for module " + ns.getName() + ", leaving unchanged");
									break;
								}

								suggestedModuleNames.put(ns, suggestedName);
								
								// Update namespace (module) to use new name
								// suggestedModuleNames is created in case this is later 
								// extended to have a GUI window for the user to accept/modify
								// names before updating, in which case this update should
								// happen elsewhere.
								monitor.setMessage("Updating module name of " + ns.getName() + "...");
								String newName = suggestedName;
								int num = 1;
								while (!CodecutUtils.getMatchingNamespaces(newName, Arrays.asList(currentProgram.getGlobalNamespace()), currentProgram).isEmpty()) {
									newName = suggestedName.concat(Integer.toString(num));
									num++;
								}
								Namespace newNs = null;
								int transactionId = currentProgram.startTransaction("ns");
								try {
									newNs = currentProgram.getSymbolTable().createNameSpace(ns.getParentNamespace(), newName, SourceType.USER_DEFINED);
									Msg.info(this, "Created NS with new name " + newName + " for module " + ns.getName());
								}
								catch (DuplicateNameException ex) {
									Msg.error(this, "Failed when trying to find and set name for suggested name " + suggestedName);
									currentProgram.endTransaction(transactionId, false);
								}
								currentProgram.endTransaction(transactionId, true);
								
								try {
									CodecutUtils.renameNamespace(currentProgram, ns, newNs);
									Msg.info(this, "Namespace " + ns.getName() + " renamed to " + newNs.getName());
								} catch (Exception ex) {
									Msg.info(this, "Exception when renaming namespace " + ns.getName() + ": " + ex.getMessage());
									
								}
							}
							numRemaining--;
							monitor.setProgress(startCount - numRemaining);
						}
						else { // Task cancelled
							suggestedModuleNames.clear();
							suggestedModuleNames = null;
						}
					}
							
				} catch (Exception e) {
					Msg.error(this, "Module name guessing failed: " + e);
					e.printStackTrace();
				}
				CodecutUtils.setUpdating(false);
				
			}
		};
		
		new TaskLauncher(guessNamesTask, null, 250);
	}
	
	private void getModuleStrings() {
		try {	
			SymbolTable symbolTable = currentProgram.getSymbolTable();
			ReferenceManager refManager = currentProgram.getReferenceManager();
			
			TaskMonitor monitor = new TaskMonitorAdapter();
			monitor.setCancelEnabled(true);
			Listing listing = currentProgram.getListing();
			monitor.initialize(listing.getNumDefinedData());
			
			Accumulator<ProgramLocation> accumulator = new ListAccumulator<>();

			Swing.allowSwingToProcessEvents();
			for (Data stringInstance : DefinedDataIterator.definedStrings(currentProgram)) {
				Address strAddr = stringInstance.getAddress();
				ReferenceIterator refIterator = refManager.getReferencesTo(strAddr);
				while (refIterator.hasNext()) {
					Reference ref = refIterator.next();
					Namespace refNamespace = symbolTable.getNamespace(ref.getFromAddress());
					Namespace parentNs = refNamespace.getParentNamespace();
					String str = StringDataInstance.getStringDataInstance(stringInstance).getStringValue();
					
					// parent namespace is correct one to use BUT MAY BE NULL IF GLOBAL WAS ORIGINAL
					Namespace module;
					if (parentNs != null) {
						module = parentNs;
					}
					else {
						module = refNamespace;
					}
					
					List<String> list = stringMap.get(module);
					if (list != null) {
						list.add(str);
						stringMap.put(module, list);
					}
					else {
						List<String> newList = new ArrayList<String>();
						newList.add(str);
						stringMap.put(module, newList);
					}
				}
				
				ProgramLocation pl = new ProgramLocation(currentProgram, stringInstance.getMinAddress(), 
						stringInstance.getComponentPath(), null, 0, 0, 0);
				
				accumulator.add(pl);
				//monitor.checkCanceled();
				monitor.incrementProgress(1);
			}
			
		} catch (Exception e) {
			Msg.error(this, "Error when getting strings for each module: " + e);
			e.printStackTrace();
		}
	}
	

	private void importModuleMap() {
		Task importModMapTask = new Task("Import Module Map", true, true, true) {
			@Override 
			public void run(TaskMonitor monitor) {
				monitor.setMessage("Importing module map file...");
				Program program = GhidraProgramUtilities.getCurrentProgram(tool);

				List<Symbol> functionList = new ArrayList<>();
				SymbolTable symbolTable = program.getSymbolTable();
				SymbolIterator symIter = symbolTable.getDefinedSymbols();
				while (symIter.hasNext()) {
					Symbol symbol = symIter.next();
					if (symbol.getSymbolType() == SymbolType.FUNCTION) {
						functionList.add(symbol);
					}
				}
				long startCount = functionList.size(); 
				long numRemaining = functionList.size(); 
				monitor.initialize(startCount);
				try {
					File mapFile = loadMapFile();
					if (mapFile != null) {
						FileReader fr = new FileReader(mapFile.getAbsoluteFile());
						BufferedReader br = new BufferedReader(fr);
						
						String line = br.readLine();
						while (line != null) {
							String[] tokens = line.split("[ ]+");
							if (tokens.length == 5) {
								if (tokens[1].equals(".text")) {
									String name = tokens[4];
									String startStr = tokens[2].substring(2);
									long length = Long.valueOf(tokens[3].substring(2), 16);
									long end = Long.valueOf(startStr, 16) + length;
									String endStr = Long.toHexString(end);
		
									Address[] startAddr = program.parseAddress(startStr);
									Address[] endAddr = program.parseAddress(endStr);
									AddressRange addressRange = new AddressRangeImpl(startAddr[0], endAddr[0]);
									
									int transactionID = program.startTransaction("nsImport");
									for (Symbol sym : functionList) {
										if (addressRange.contains(sym.getAddress())) {
											Namespace ns = null;
											ns = symbolTable.getNamespace(name, null);
											if (ns == null) {
												try {
													monitor.setMessage("Creating namespace " + name);
													Msg.info(this, "Creating namespace " + name);
													ns = symbolTable.createNameSpace(null, name, SourceType.USER_DEFINED);
												}
												catch (Exception e) {
													Msg.info(this, "Exception when attempting to create namespace " 
																+ name + " " + e.getMessage());
													program.endTransaction(transactionID, false);
													break;
												}
											}
											if (ns != null) {
												try {
													monitor.setMessage("Setting namespace of " + sym.getName() + " to " + ns.getName());
													Msg.info(this, "Setting namespace of " + sym.getName() + " to " + ns.getName());
													sym.setNamespace(ns);
												}
												catch (Exception e) {
													Msg.info(this, "Exception when attempting to change namespace of symbol " 
															+ sym.getName() + " to " + ns.getName());
													program.endTransaction(transactionID, false);
													break;
												}
											}
											numRemaining--; 
											monitor.setProgress(startCount - numRemaining);
										}
									}
									program.endTransaction(transactionID, true);
								}
								
							}							
							line = br.readLine();

						}
						br.close();
					}
				}
				catch (IOException e) {
					Msg.error(this, "Map Import Failed", e);
				}
			}
		};
		new TaskLauncher(importModMapTask, null, 250);
	}
	
	
	private void exportModuleMap() {
		Program program = GhidraProgramUtilities.getCurrentProgram(tool);
		
		try {
			File mapFile = getMapFile();
			if (mapFile != null) {
				FileWriter fw = new FileWriter(mapFile.getAbsoluteFile());
		        BufferedWriter bw = new BufferedWriter(fw);
				List<Namespace> nsList = CodecutUtils.getAllNamespaces(program);
				Iterator<Namespace> it = nsList.iterator();
				
				while(it.hasNext()) {
					Namespace ns = it.next();
					String modName = ns.getName();
					AddressSetView addrSet = ns.getBody();
					
					AddressRange moduleRange = CodecutUtils.getNamespaceRange(program, ns);
					if (moduleRange != null) {
						long modBase = addrSet.getMinAddress().getAddressableWordOffset();
						long modMax = addrSet.getMaxAddress().getAddressableWordOffset(); 
						
						long modSize = modMax - modBase;
						String modSizeStr = "0x" + Long.toHexString(modSize);
						Msg.info(this, "Module " + ns.getName() 
									+ " base=0x" + Long.toHexString(modBase) 
									+ " max=0x" + Long.toHexString(modMax)
									+ " size=0x" + Long.toHexString(modSize));
						String moduleStr = String.format(" %-11s 0x%016x %11s %s\n", ".text", 
								modBase, modSizeStr, modName);
						bw.write(moduleStr);
					}
				}
				bw.close();	
			}
		}
		catch (IOException e) {
			Msg.showError(this, this.symProvider.getComponent(), "Map Export Failed", e.getMessage());
		}
		
	}
	
	private File loadMapFile() {
		GhidraFileChooser fileChooser = new GhidraFileChooser(this.symProvider.getComponent());
		String dir = Preferences.getProperty(Preferences.LAST_TOOL_IMPORT_DIRECTORY );
		if (dir != null) {
			File file = new File(dir);
			fileChooser.setCurrentDirectory(file);
			fileChooser.setTitle("Choose Map File to Import");
			fileChooser.setApproveButtonText("Choose Import Map File");
			fileChooser.setApproveButtonToolTipText("Choose existing map file to import");
		}
		fileChooser.rescanCurrentDirectory();
		File file = fileChooser.getSelectedFile();
		if (file != null) {
			File parent = file.getParentFile();
			if (parent != null) {
				Preferences.setProperty(Preferences.LAST_TOOL_IMPORT_DIRECTORY, parent.getAbsolutePath());
			}
			if (!file.getName().endsWith(".map")) {
				Msg.showInfo(this,  this.symProvider.getComponent(), 
						"Invalid Map File", "Unrecognized extension for map file.");
			}
			if (file.exists()) {
				return file;
			}
		}
		return null;
	}
	
	protected File getMapFile() {
		GhidraFileChooser fileChooser = new GhidraFileChooser(this.symProvider.getComponent());
		String dir = Preferences.getProperty(Preferences.LAST_TOOL_EXPORT_DIRECTORY);
		if (dir != null) {
			File file = new File(dir);
			fileChooser.setCurrentDirectory(file);
			fileChooser.setTitle("Choose Save Map File");
			fileChooser.setApproveButtonText("Choose Save Map File");
			fileChooser.setApproveButtonToolTipText("Choose filename for map file");
		}
		fileChooser.rescanCurrentDirectory();
		File file = fileChooser.getSelectedFile();
		if (file != null) {
			File parent = file.getParentFile();
			if (parent != null) {
				Preferences.setProperty(Preferences.LAST_TOOL_EXPORT_DIRECTORY, parent.getAbsolutePath());
			}
			String name = file.getName();
			if (!file.getName().endsWith(".map")) {
				file = new File(file.getParentFile(), name + ".map");
			}
			if (file.exists()) {
				if (OptionDialog.showOptionDialog(this.symProvider.getComponent(), "Overwrite Existing File?", 
						"The file " + file.getAbsolutePath() + " already exists. \nDo you want to overwrite it?", 
						"Yes", OptionDialog.QUESTION_MESSAGE) != OptionDialog.OPTION_ONE) {
					file = null;
				}
				else {
					try {
						// delete existing file
						deleteFile(file);
					}
					catch (IOException e) {
						Msg.showError(this, this.symProvider.getComponent(), "Map File Overwrite Failed", e.getMessage());
						return null;
					}
				}
			}
		}
		
		return file;	
	}
	
	private static void deleteFile(File file) throws IOException {
		if (file.exists() && !file.delete()) {
			throw new IOException("File is in use or write protected");
		}
		
	}
	
	// a HACK to make the given action the selected action
	private void reselectAction(ToggleDockingAction action) {
		// We must reselect the action and trigger the proper painting of its button.  We do this
		// by indirectly triggering property change events, which will not happen if we do not
		// change the state of the action.  So, the action is given to us in a selected state and
		// we must leave it in a selected state while trigger a property change, which is done
		// by toggling the state
		action.setSelected(false);
		action.setSelected(true);
	}
	
	public boolean getMapping(PluginTool tool) {
/*		try {
			decExtService.updateMapping();
		} catch (Exception e) {
			e.printStackTrace();
			return false; 
		} 
		Msg.info(new Object(),  decExtService.getMapping());
*/
		return true;
	}
	
	protected File getCFile() {
		GhidraFileChooser fileChooser = new GhidraFileChooser(this.symProvider.getComponent());
		String dir = Preferences.getProperty(Preferences.LAST_TOOL_EXPORT_DIRECTORY);
		if (dir != null) {
			File file = new File(dir);
			fileChooser.setCurrentDirectory(file);
			fileChooser.setTitle("Choose Save C File");
			fileChooser.setApproveButtonText("Choose Save C File");
			fileChooser.setApproveButtonToolTipText("Choose filename for C file");
		}
		fileChooser.rescanCurrentDirectory();
		File file = fileChooser.getSelectedFile();
		if (file != null) {
			File parent = file.getParentFile();
			if (parent != null) {
				Preferences.setProperty(Preferences.LAST_TOOL_EXPORT_DIRECTORY, parent.getAbsolutePath());
			}
			String name = file.getName();
			if (!file.getName().endsWith(".c")) {
				file = new File(file.getParentFile(), name + ".c");
			}
			if (file.exists()) {
				if (OptionDialog.showOptionDialog(this.symProvider.getComponent(), "Overwrite Existing File?", 
						"The file " + file.getAbsolutePath() + " already exists. \nDo you want to overwrite it?", 
						"Yes", OptionDialog.QUESTION_MESSAGE) != OptionDialog.OPTION_ONE) {
					file = null;
				}
				else {
					try {
						// delete existing file
						deleteFile(file);
					}
					catch (IOException e) {
						Msg.showError(this, this.symProvider.getComponent(), "C File Overwrite Failed", e.getMessage());
						return null;
					}
				}
			}
		}
		
		return file;	
	}
	public void exportC(String startAddr, String endAddr) {
		File file = getCFile();
		CExporter cExporter = new CExporter(startAddr, endAddr, file);
		try {
			GhidraState state = new GhidraState(tool, tool.getProject(), GhidraProgramUtilities.getCurrentProgram(tool), null, null, null);
			ConsoleTaskMonitor monitor = new ConsoleTaskMonitor(); 
			PrintWriter pw = new PrintWriter(file);
			cExporter.execute(state, monitor, pw);
		} catch (Exception e) {
			e.printStackTrace();
		} 
	
	}
	private class CExporter extends JythonScript{
		Program program = GhidraProgramUtilities.getCurrentProgram(tool);
		GhidraState state = new GhidraState(tool, tool.getProject(), program, null, null, null);
		String start_addr; 
		String end_addr;
		String outfile; 
		String path; 
		
		public CExporter(String start, String end, File file) {
			this.start_addr = start;
			this.end_addr = end; 
			this.outfile = file.getAbsolutePath(); 
			this.state.addEnvironmentVar("ghidra.python.interpreter", GhidraJythonInterpreter.get());
			this.path = this.outfile.substring(0, this.outfile.lastIndexOf("/")+1);
		}
		@Override
		public void run() {
			//Leaving this in for if/when we can reintroduce DWARF output
			//this is what ghidra2dwarf was using
			//String[] args = {"-c", start_addr, end_addr, outfile, path}; 
			String[] args = {start_addr, end_addr, outfile}; 
			try {
				//runScript("ghidra2dwarf.py", args);
				runScript("range.py",args);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		
	}
	private class OFileExporter extends GhidraScript{
		
		GhidraState state;
		PrintWriter pw; 
		String objName; 
		ConsoleTaskMonitor monitor = new ConsoleTaskMonitor(); 

		public OFileExporter(GhidraState gstate, String objName){
			this.state = gstate;
			this.objName = objName; 
		}
		@Override
		protected void run() throws Exception {
			String [] scriptArgs = {this.objName};
			String path = state.getCurrentProgram().getExecutablePath(); 
			this.pw = new PrintWriter(path.substring(0, path.lastIndexOf("/")+1) + this.objName + "_modified.o"); 
			this.set(state, monitor, pw); 
			runScript("OutputObjFile.py", scriptArgs, this.state); 
			
		}
		
	}
	
		private void createGraphActions() {
			DockingAction showProviderAction = new DockingAction(SHOW_PROVIDER_ACTION_NAME, getName(), true) {
				@Override
				public void actionPerformed(ActionContext context) {
					graphProvider.setVisible(true);
				}
			};
			tool.addAction(showProviderAction);
			
			DockingAction addToGraphAction = new DockingAction("Add Namespace to Graph", getName(), KeyBindingType.SHARED) {
				@Override 
				public void actionPerformed(ActionContext context) {
					graphProvider.addToWhitelist(symProvider.getCurrentSymbol().getParentNamespace());
					checklistProvider.buildTable();
				}
				
				@Override 
				public boolean isEnabledForContext(ActionContext context) {
					return symProvider.getCurrentSymbol() != null;
				}
			};
			addToGraphAction.setPopupMenuData(
					new MenuData(new String[] { "Add Namespace to Graph" }, "0"));
			addToGraphAction.setDescription("Add this Namespace to the CodeCut Graph");
			tool.addLocalAction(symProvider, addToGraphAction);
			
			DockingAction displayCodeCutGraphAction = 
					new DockingAction("Display_CodeCut_Graph", this.getName()) {
				@Override
				public boolean isEnabledForContext(ActionContext context) {
					return symProvider.getCurrentSymbol() != null;
				}
				
				@Override
				public void actionPerformed(ActionContext context) {
					graphProvider.setVisible(true);
				}
			};
			MenuData graphModule = new MenuData(new String[] {ToolConstants.MENU_GRAPH, "Display CodeCut Object Graph"}, null, "Display CodeCut Object Graph");
			graphModule.setMenuSubGroup("1");
			displayCodeCutGraphAction.setMenuBarData(graphModule);
			displayCodeCutGraphAction.setHelpLocation(null);
			displayCodeCutGraphAction.setAddToAllWindows(true);
			tool.addAction(displayCodeCutGraphAction);
			
		}
		
		void showProvider() {
			graphProvider.setVisible(true);
		}
		
		public Address getCurrentAddress() {
			if (currentLocation == null) {
				return null;
			}
			return currentLocation.getAddress();
		}
		
		public VisualGraphOptions getOptions() {
			return vgOptions;
		}
		
		public ProgramLocation getCurrentLocation() {
			return currentLocation;
		}
		
		private void initializeGraphOptions() {
			ToolOptions options = tool.getOptions(ToolConstants.GRAPH_OPTIONS);
			options.addOptionsChangeListener(this);
			
			HelpLocation help = new HelpLocation(getName(), "Options");
			
			Options graphOptions = options.getOptions(GRAPH_NAME);
			vgOptions.registerOptions(graphOptions, help);
			vgOptions.loadOptions(graphOptions);
			graphProvider.optionsChanged();
		}
		
		@Override
		public void optionsChanged(ToolOptions options, String optionName, Object oldValue, Object newValue) throws OptionsVetoException {
			
			Options graphOptions = options.getOptions(GRAPH_NAME);
			vgOptions.loadOptions(graphOptions);
			graphProvider.optionsChanged();
		}
		
		@Override
		public void locationChanged(ProgramLocation loc) {
			locationUpdater.update();
		}
		
		private void doLocationChanged() {
			graphProvider.locationChanged(getCurrentLocation());
		}
		
		public void handleProviderLocationChanged(ProgramLocation location) {
			GoToService goTo = getGoToService();
			if (goTo == null) {
				return;
			}
			
			SystemUtilities.runSwingLater(() -> {
				goTo.goTo(location);
			});
		}
		
		public void createChecklistActions() {
			String popupGroup = "0"; 
			
			DockingAction showChecklistAction = new DockingAction("Show Namespaces in Graph Filter", getName(), KeyBindingType.SHARED) {
				@Override
				public void actionPerformed(ActionContext context) {
					checklistProvider.open();
					checklistProvider.buildTable();
				}
				
				@Override
				public boolean isEnabledForContext(ActionContext context) {
					return symProvider.getCurrentSymbol() != null;
				}
			};
			showChecklistAction.setPopupMenuData(
					new MenuData(new String[] { "Show Namespaces in Graph Filter" }, popupGroup));
			showChecklistAction.setDescription("Show Namespaces that have been added to the CodeCut Graph");
			tool.addLocalAction(symProvider, showChecklistAction);
		}
}
