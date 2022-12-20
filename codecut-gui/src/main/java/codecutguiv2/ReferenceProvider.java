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

import java.awt.event.MouseEvent;

import javax.swing.ImageIcon;
import javax.swing.JComponent;

import docking.ActionContext;
import docking.WindowPosition;
import ghidra.app.context.ProgramActionContext;
import ghidra.app.util.SymbolInspector;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.HelpLocation;
import ghidra.util.Swing;
import ghidra.util.table.GhidraTable;
import resources.ResourceManager;

class ReferenceProvider extends ComponentProviderAdapter {

	private static final ImageIcon ICON = ResourceManager.loadImage("images/table_go.png");

	private CodeCutGUIPlugin plugin;
	private SymbolReferenceModel referenceKeyModel;
	private ReferencePanel referencePanel;
	private SymbolRenderer renderer;

	ReferenceProvider(CodeCutGUIPlugin plugin) {
		super(plugin.getTool(), "Symbol References", plugin.getName(), ProgramActionContext.class);
		this.plugin = plugin;

		setIcon(ICON);
		addToToolbar();
		setHelpLocation(new HelpLocation(plugin.getName(), "Symbol_References"));
		setWindowGroup("codecutTable");
		setIntraGroupPosition(WindowPosition.RIGHT);

		renderer = new SymbolRenderer();

		referenceKeyModel =
			new SymbolReferenceModel(plugin.getBlockModelService(), plugin.getTool());
		referencePanel =
			new ReferencePanel(this, referenceKeyModel, renderer, plugin.getGoToService());

		addToTool();
	}

	void dispose() {
		referencePanel.dispose();
		plugin = null;
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		Program program = plugin.getProgram();
		if (program == null) {
			return null;
		}
		return new ProgramActionContext(this, program);
	}

	void setCurrentSymbol(Symbol symbol) {
		referenceKeyModel.setCurrentSymbol(symbol);
	}

	void symbolChanged(Symbol symbol) {
		if (isVisible()) {
			referenceKeyModel.symbolChanged(symbol);
		}
	}

	void symbolRemoved(Symbol symbol) {
		if (isVisible()) {
			referenceKeyModel.symbolRemoved(symbol);
		}
	}

	void symbolAdded(Symbol sym) {
		if (isVisible()) {
			referenceKeyModel.symbolAdded(sym);
		}
	}

	void setProgram(Program program, SymbolInspector inspector) {
		renderer.setSymbolInspector(inspector);
		if (isVisible()) {
			referenceKeyModel.setProgram(program);
		}
	}

	void reload() {
		if (isVisible()) {
			referenceKeyModel.reload();
		}
	}

	void showReferencesTo() {
		referenceKeyModel.showReferencesTo();
	}

	void showInstructionsFrom() {
		referenceKeyModel.showInstructionReferencesFrom();
	}

	void showDataFrom() {
		referenceKeyModel.showDataReferencesFrom();
	}

	public GhidraTable getTable() {
		return referencePanel.getTable();
	}

	private String generateSubTitle() {
		return "(" + referenceKeyModel.getDescription() + ")";
	}

	void open() {
		setVisible(true);
	}

	@Override
	public void componentHidden() {
		referenceKeyModel.setProgram(null);
	}

	@Override
	public void componentShown() {
		referenceKeyModel.setProgram(plugin.getProgram());

		// Note: this is a bit of a hack--if we do this during a tool's restore process, then
		//       there is a chance that the Symbol Provider has not yet been re-loaded.   This
		//       is only needed due to the odd dependency of this provider upon the Symbol Provider.
		Swing.runLater(plugin::openSymbolProvider);
	}

	@Override
	public JComponent getComponent() {
		return referencePanel;
	}

	public void updateTitle() {
		setSubTitle(generateSubTitle());
	}
}
