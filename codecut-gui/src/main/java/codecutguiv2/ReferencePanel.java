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
import java.awt.Dimension;

import javax.swing.JPanel;
import javax.swing.ListSelectionModel;
import javax.swing.event.TableModelListener;
import javax.swing.table.TableColumn;
import javax.swing.table.TableModel;

import ghidra.app.services.GoToService;
import ghidra.program.model.symbol.Reference;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.GhidraThreadedTablePanel;

/**
 * 
 * 
 */
class ReferencePanel extends JPanel {

	private ReferenceProvider referenceProvider;
	private GhidraTable refTable;
	private TableModelListener listener;
	private GhidraThreadedTablePanel<Reference> threadedTablePanel;

	ReferencePanel(ReferenceProvider provider, SymbolReferenceModel model, SymbolRenderer renderer,
			GoToService gotoService) {

		super(new BorderLayout());

		referenceProvider = provider;

		threadedTablePanel = new GhidraThreadedTablePanel<>(model);

		refTable = threadedTablePanel.getTable();
		refTable.setAutoLookupColumn(SymbolReferenceModel.LABEL_COL);
		refTable.setName("ReferenceTable");//used by JUnit...
		refTable.setPreferredScrollableViewportSize(new Dimension(250, 200));
		refTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		refTable.installNavigation(gotoService, gotoService.getDefaultNavigatable());

		this.listener = e -> referenceProvider.updateTitle();
		refTable.getModel().addTableModelListener(listener);

		for (int i = 0; i < refTable.getColumnCount(); i++) {
			TableColumn column = refTable.getColumnModel().getColumn(i);
			if (column.getModelIndex() == SymbolReferenceModel.LABEL_COL) {
				column.setCellRenderer(renderer);
			}
		}

		add(threadedTablePanel, BorderLayout.CENTER);
	}

	GhidraTable getTable() {
		return refTable;
	}

	void dispose() {
		TableModel model = refTable.getModel();
		model.removeTableModelListener(listener);
		threadedTablePanel.dispose();
		refTable.dispose();
		referenceProvider = null;
	}
}
