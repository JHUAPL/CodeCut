/* ###
 * © 2022 The Johns Hopkins University Applied Physics Laboratory LLC (JHU/APL).  
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

import java.awt.BorderLayout;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;
import javax.swing.event.ListSelectionListener;
import javax.swing.event.TableModelListener;
import javax.swing.table.TableColumn;

import org.jdom.Element;

import docking.widgets.checkbox.GCheckBox;
import docking.widgets.table.DefaultRowFilterTransformer;
import docking.widgets.table.RowFilterTransformer;
import ghidra.app.services.GoToService;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.util.ProgramSelection;
import ghidra.util.table.*;

class SymbolPanel extends JPanel {

	private static final boolean FILTER_NAME_ONLY_DEFAULT = true;

	private static final String FILTER_SETTINGS_ELEMENT_NAME = "FILTER_SETTINGS";

	private SymbolProvider symProvider;
	private SymbolTableModel tableModel;
	private GhidraTable symTable;
	private TableModelListener listener;
	private FilterDialog filterDialog;
	private GhidraThreadedTablePanel<Symbol> threadedTablePanel;
	private Namespace namespace;
	private ListSelectionListener selectionListener;

	SymbolPanel(SymbolProvider provider, SymbolTableModel model, SymbolRenderer renderer,
			final PluginTool tool, GoToService gotoService, Namespace namespace) {

		super(new BorderLayout());

		this.symProvider = provider;
		this.tableModel = model;
		this.namespace = namespace;
		this.selectionListener = new SharedListSelectionListener(namespace, provider);

		threadedTablePanel = new GhidraThreadedTablePanel<>(model);

		this.listener = e -> symProvider.updateTitle();

		symTable = threadedTablePanel.getTable();
		symTable.setAutoLookupColumn(SymbolTableModel.LABEL_COL);
		symTable.setName("SymbolTable");//used by JUnit...
		symTable.setRowSelectionAllowed(true);
		symTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
		symTable.getSelectionManager().addListSelectionListener(selectionListener);
		
		symTable.getModel().addTableModelListener(listener);
		symTable.getSelectionModel().addListSelectionListener(e -> {
			if (!e.getValueIsAdjusting()) {
				handleTableSelection();
				tool.contextChanged(symProvider);
			}
		});

		GoToService goToService = tool.getService(GoToService.class);
		symTable.installNavigation(goToService, goToService.getDefaultNavigatable());
		
		symTable.setDragEnabled(true);
		symTable.setDropMode(DropMode.ON);
		symTable.setTransferHandler(new CodeCutTransferHandler());
		
		for (int i = 0; i < symTable.getColumnCount(); i++) {
			TableColumn column = symTable.getColumnModel().getColumn(i);
			column.setCellRenderer(renderer);
			if (column.getModelIndex() == SymbolTableModel.LABEL_COL) {
				column.setCellEditor(new SymbolEditor());
			}
		}

		add(threadedTablePanel, BorderLayout.CENTER);

		filterDialog = symProvider.filterDialog;
	}
	
	ProgramSelection getProgramSelection() {
		return symTable.getProgramSelection();
	}

	void dispose() {
		symTable.getModel().removeTableModelListener(listener);
		symTable.dispose();
		threadedTablePanel.dispose();
		symProvider = null;
		filterDialog.close();
		filterDialog = null;
	}

	void setFilter() {
		if (filterDialog == null) {
			return;
		}
		if (symTable.isEditing()) {
			symTable.editingCanceled(null);
		}
		symProvider.setCurrentSymbol(null);
		symTable.clearSelection();
		filterDialog.adjustFilter(symProvider, tableModel);
	}

	NewSymbolFilter getFilter() {
		return filterDialog.getFilter();
	}

	FilterDialog getFilterDialog() {
		return filterDialog;
	}

	void readConfigState(SaveState saveState) {
		Element filterElement = saveState.getXmlElement(FILTER_SETTINGS_ELEMENT_NAME);
		if (filterElement != null) {
			filterDialog.restoreFilter(filterElement);
			tableModel.setFilter(filterDialog.getFilter());
		}
	}

	void writeConfigState(SaveState saveState) {
		Element filterElement = filterDialog.saveFilter();
		saveState.putXmlElement(FILTER_SETTINGS_ELEMENT_NAME, filterElement);
	}

	private void handleTableSelection() {
		int selectedRowCount = symTable.getSelectedRowCount();

		if (selectedRowCount == 1) {
			int selectedRow = symTable.getSelectedRow();
			Symbol symbol = symProvider.getSymbolForRow(selectedRow);
			symProvider.setCurrentSymbol(symbol);
		}
		else {
			symProvider.setCurrentSymbol(null);
		}
	}

	int getActualSymbolCount() {
		return symTable.getRowCount();
	}

	List<Symbol> getSelectedSymbols() {
		int[] rows = symTable.getSelectedRows();
		return tableModel.getRowObjects(rows);
	}

	GhidraTable getTable() {
		return symTable;
	}
	
	Namespace getNamespace() {
		return namespace;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private static class NameOnlyRowTransformer implements RowFilterTransformer<Symbol> {
		private List<String> list = new ArrayList<>();

		@Override
		public List<String> transform(Symbol rowObject) {
			list.clear();
			if (rowObject != null) {
				// The toString() returns the name for the symbol, which may be cached.  Calling
				// toString() will also avoid locking for cached values.
				list.add(rowObject.toString());
			}
			return list;
		}

		@Override
		public int hashCode() {
			// not meant to put in hashing structures; the data for equals may change over time
			throw new UnsupportedOperationException();
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj) {
				return true;
			}
			if (obj == null) {
				return false;
			}
			if (getClass() != obj.getClass()) {
				return false;
			}
			return true;
		}
	}
	SymbolTableModel getModel() {
		return this.tableModel; 
	}
}
