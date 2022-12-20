/* ###
* © 2022 The Johns Hopkins University Applied Physics Laboratory LLC
* (JHU/APL).
*
* NO WARRANTY, NO LIABILITY. THIS MATERIAL IS PROVIDED “AS IS.” JHU/APL
* MAKES NO REPRESENTATION OR WARRANTY WITH RESPECT TO THE PERFORMANCE OF
* THE MATERIALS, INCLUDING THEIR SAFETY, EFFECTIVENESS, OR COMMERCIAL
* VIABILITY, AND DISCLAIMS ALL WARRANTIES IN THE MATERIAL, WHETHER
* EXPRESS OR IMPLIED, INCLUDING (BUT NOT LIMITED TO) ANY AND ALL IMPLIED
* WARRANTIES OF PERFORMANCE, MERCHANTABILITY, FITNESS FOR A PARTICULAR
* PURPOSE, AND NON-INFRINGEMENT OF INTELLECTUAL PROPERTY OR OTHER THIRD
* PARTY RIGHTS. ANY USER OF THE MATERIAL ASSUMES THE ENTIRE RISK AND
* LIABILITY FOR USING THE MATERIAL. IN NO EVENT SHALL JHU/APL BE LIABLE
* TO ANY USER OF THE MATERIAL FOR ANY ACTUAL, INDIRECT, CONSEQUENTIAL,
* SPECIAL OR OTHER DAMAGES ARISING FROM THE USE OF, OR INABILITY TO USE,
* THE MATERIAL, INCLUDING, BUT NOT LIMITED TO, ANY DAMAGES FOR LOST
* PROFITS.
*
* This material is based upon work supported by the Defense Advanced Research
* Projects Agency (DARPA) and Naval Information Warfare Center Pacific (NIWC Pacific)
* under Contract Number N66001-20-C-4024.
*
* HAVE A NICE DAY.
*/

package codecutguiv2;

import java.awt.event.KeyEvent;
import java.awt.event.MouseEvent;
import java.util.Iterator;
import java.util.List;

import javax.swing.ImageIcon;
import javax.swing.JComponent;


import docking.ActionContext;
import docking.DockingUtils;
import docking.action.KeyBindingData;
import ghidra.app.context.ProgramActionContext;
import ghidra.app.context.ProgramSymbolActionContext;
import ghidra.app.util.SymbolInspector;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.table.GhidraTable;
import resources.ResourceManager;

class SymbolProvider extends ComponentProviderAdapter {

	private static final ImageIcon ICON = ResourceManager.loadImage("images/table.png");

	private CodeCutGUIPlugin plugin;
	private SymbolRenderer renderer;
	private SymbolTableModel symbolKeyModel;
	private NamespacePanel namespacePanel;
	public FilterDialog filterDialog; 
	
	SymbolProvider(CodeCutGUIPlugin plugin) {
		super(plugin.getTool(), "CodeCut Table", plugin.getName(), ProgramActionContext.class);
		this.plugin = plugin;

		setIcon(ICON);
		addToToolbar();
		setKeyBinding(new KeyBindingData(KeyEvent.VK_M, DockingUtils.CONTROL_KEY_MODIFIER_MASK));

		setHelpLocation(new HelpLocation(plugin.getName(), "CodeCut_Table"));
		setWindowGroup("codecutTable");
		renderer = new SymbolRenderer();
		filterDialog = new FilterDialog(plugin.getTool());

		symbolKeyModel = new SymbolTableModel(plugin.getProgram(), this, plugin.getTool());
        namespacePanel = new NamespacePanel(plugin.getProgram(), plugin.getTool(), this, renderer);
		namespacePanel.doLoad();
		addToTool();
	}
	

	void updateTitle() {
		setSubTitle(generateSubTitle());
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		Program program = plugin.getProgram();
		if (program == null) {
			return null;
		}

		List<Symbol> symbols = namespacePanel.getSelectedSymbols();
		return new ProgramSymbolActionContext(this, program, symbols, getTable());
	}

	void deleteSymbols() {
		List<Symbol> rowObjects = namespacePanel.getSelectedSymbols();
		symbolKeyModel.delete(rowObjects, plugin.getProgram());
	}

	void setFilter() {
		namespacePanel.setFilter();
	}

	Symbol getCurrentSymbol() {
		List<Symbol> rowObjects = namespacePanel.getSelectedSymbols();
		if (rowObjects != null && rowObjects.size() >= 1) {
			return rowObjects.get(0);
		}
		return null;
	}

	Symbol getSymbolForRow(int row) {
		return symbolKeyModel.getRowObject(row);
	}

	void setCurrentSymbol(Symbol symbol) {
		plugin.getReferenceProvider().setCurrentSymbol(symbol);
	}

	Symbol getSymbol(long id) {
		return symbolKeyModel.getSymbol(id);
	}

	void dispose() {
		symbolKeyModel.dispose();
		namespacePanel.dispose();
		plugin = null;
	}

	void reload() {
		if (isVisible()) {
			symbolKeyModel.reload();
			namespacePanel.setProgram(plugin.getProgram());
			namespacePanel.doLoad();
		}
	}

	void symbolAdded(Symbol s) {
		if (isVisible()) {
			symbolKeyModel.symbolAdded(s);
			namespacePanel.doLoad();
		}
	}

	void symbolRemoved(Symbol s) {
		if (isVisible()) {
			symbolKeyModel.symbolRemoved(s);
			namespacePanel.doLoad();
		}
	}

	void symbolChanged(Symbol s) {
		if (isVisible()) {
			symbolKeyModel.symbolChanged(s);
		}
		if (CodecutUtils.transferring()) {
			namespacePanel.doLoad();
			CodecutUtils.setTransferring(false);
		}
	}

	void setProgram(Program program, SymbolInspector inspector) {
		renderer.setSymbolInspector(inspector);
		namespacePanel.setProgram(program);
		if (isVisible()) {
			symbolKeyModel.reload(program);
			namespacePanel.doLoad();
		}
	}

	GhidraTable getTable() {
		return namespacePanel.getTable();
	}
	
	List<GhidraTable> getAllTables() {
		return namespacePanel.getAllTables();
	}
	
	int getSelectedRowCount() {
		return namespacePanel.getSelectedRowCount();
	}

	NewSymbolFilter getFilter() {
		return namespacePanel.getFilter();
	}
	
	Iterator<SymbolPanel> getSymPanels(){
		return namespacePanel.getPanels(); 
	}
	
	private String generateSubTitle() {
		SymbolFilter filter = symbolKeyModel.getFilter();

		int rowCount = symbolKeyModel.getRowCount();
		int unfilteredCount = symbolKeyModel.getUnfilteredRowCount();

		if (rowCount != unfilteredCount) {
			return " (Text filter matched " + rowCount + " of " + unfilteredCount + " symbols)";
		}
		if (filter.acceptsAll()) {
			return "(" + namespacePanel.getActualSymbolCount() + " Symbols)";
		}
		return "(Filter settings matched " + namespacePanel.getActualSymbolCount() + " Symbols)";

	}

	void open() {
		if (!isVisible()) {
			setVisible(true);
		}
	}

	@Override
	public void componentHidden() {
		symbolKeyModel.reload(null);
		if (plugin != null) {
			plugin.closeReferenceProvider();
		}
	}

	@Override
	public void componentShown() {
		symbolKeyModel.reload(plugin.getProgram());
		namespacePanel.setProgram(plugin.getProgram());
		namespacePanel.doLoad();
	}

	@Override
	public JComponent getComponent() {
		return namespacePanel;
	}

	void readConfigState(SaveState saveState) {
		namespacePanel.readConfigState(saveState);
	}

	void writeConfigState(SaveState saveState) {
		namespacePanel.writeConfigState(saveState);
	}
	
	void clearOtherSelections(Namespace namespace) {
		namespacePanel.clearOtherSelections(namespace);
	}

}
