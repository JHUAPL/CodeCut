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
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;
import java.util.stream.Collectors;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;


import ghidra.app.services.GoToService;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.util.Msg;
import ghidra.util.layout.PairLayout;
import ghidra.util.table.GhidraTable;

class NamespacePanel extends JPanel {
	
	private Program program;
	private PluginTool tool;
	private SymbolProvider symProvider;
	private SymbolRenderer renderer;
	private List<SymbolPanel> symPanels;
	private JPanel boxPanel;
	private JScrollPane listScroller;
	private List<GhidraTable> tables; 
	private Boolean textFiltering = false; 
	
	NamespacePanel(Program program, PluginTool tool, SymbolProvider provider, SymbolRenderer renderer) {
		BoxLayout layout = new BoxLayout(this, BoxLayout.Y_AXIS);
		this.setLayout(layout);
		
		this.program = program;
		this.tool = tool;
		this.symProvider = provider;
		this.symPanels = new ArrayList<>();
		this.tables = new ArrayList<>(); 
		this.boxPanel = null;
		this.listScroller = null;
		this.renderer = renderer;

	}
	
	public void doLoad() {
		if (program == null) {
			return;
		}
		this.removeAll();
		this.symPanels = new ArrayList<>(); 
		List<Namespace> nsList = CodecutUtils.getAllNamespaces(program);
		
		if (nsList.size() > 2) {
			nsList.sort(new Comparator<Namespace>() {
				@Override 
				public int compare(Namespace ns1, Namespace ns2) {
					Address ns1MinAddress = ns1.getBody().getMinAddress();
					Address ns2MinAddress = ns2.getBody().getMinAddress();
					if (ns1MinAddress != null && ns2MinAddress != null) {
						if (ns1MinAddress.getAddressableWordOffset() < ns2MinAddress.getAddressableWordOffset()) {
							return -1;
						}
					}
					return 1;
				}
			});
		}
		
		GoToService goToService = tool.getService(GoToService.class);
		
		boxPanel = new JPanel();
		boxPanel.setLayout(new BoxLayout(boxPanel, BoxLayout.Y_AXIS));
		Iterator<Namespace> it = nsList.iterator();
		List<String> nsNames = nsList.stream().map(ns ->ns.getName())
				.collect(Collectors.toList());
		String longest = nsNames.stream().max(Comparator.comparingInt(String::length)).get();
		JLabel longestLabel = new JLabel(longest); 
		int width = longestLabel.getPreferredSize().width; 
		while(it.hasNext()) {
			
			Namespace ns = it.next();
			AddressSetView ar = ns.getBody();
			if ((ar.getMinAddress() != null) && (ar.getMaxAddress() != null)) {
				Msg.info(this, "Add: " + ns.getName() + " " + ar.getMinAddress().toString() + " " + ar.getMaxAddress().toString());
			}
			else {
				Msg.info(this,  "Add: " + ns.getName() + " null min or max??");
			}
			SymbolIterator symIter = this.program.getSymbolTable().getSymbols(ns);
			SymbolTableModel model = new SymbolTableModel(this.program, this.symProvider, this.tool, symIter, ns);

			JPanel panel = new RowPanel(new PairLayout(6, 10), ns);
			SymbolPanel symPanel = new SymbolPanel(this.symProvider, model, this.renderer, this.tool, goToService, ns);
			JLabel label = new JLabel(ns.getName());
			int height = symPanel.getPreferredSize().height;
			int symWidth = symPanel.getPreferredSize().width;
			label.setPreferredSize(new Dimension(width, height));
			symPanel.setPreferredSize(new Dimension(symWidth, height));
			
			panel.add(label);
			panel.add(symPanel, BorderLayout.EAST);
			
			panel.setBorder(BorderFactory.createLoweredBevelBorder());
			
			int totalWidth = panel.getPreferredSize().width;
			panel.setPreferredSize(new Dimension(totalWidth, height));
			symPanels.add(symPanel);
			tables.add(symPanel.getTable());
			symPanel.getTable().setNavigateOnSelectionEnabled(true);
			boxPanel.add(panel);
		}
		
		listScroller = new JScrollPane(boxPanel);
		boxPanel.setAutoscrolls(true);
		this.add(listScroller, BorderLayout.CENTER);
		CCTableFilterPanel filterPanel = new CCTableFilterPanel(tables, symProvider, this); 
		this.add(filterPanel, BorderLayout.SOUTH);
		this.setPreferredSize(new Dimension(576, 400));
		revalidate();
		
	}

	List<Symbol> getSelectedSymbols() {
		Iterator<SymbolPanel> it = symPanels.iterator();
		List<Symbol> selectedSymbols = new ArrayList<>();
		while (it.hasNext()) {
			SymbolPanel panel = it.next();
			GhidraTable table = panel.getTable();
			int[] rows = table.getSelectedRows();
			SymbolTableModel model = (SymbolTableModel)table.getModel();
			List<Symbol> symbols = model.getRowObjects(rows);
			selectedSymbols.addAll(symbols);
		}
		return selectedSymbols;
	}

	int getSelectedRowCount() {
		Iterator<SymbolPanel> it = symPanels.iterator();
		int count = 0;
		while (it.hasNext()) {
			SymbolPanel panel = it.next();
			GhidraTable table = panel.getTable();
			count += table.getSelectedRowCount();
		}
		return count;
	}
	
	void setFilter() {
		Iterator<SymbolPanel> it = symPanels.iterator();
		while (it.hasNext()) {
			SymbolPanel panel = it.next();
			panel.setFilter();
		}
	}
	
	void dispose() {
		Iterator<SymbolPanel> it = symPanels.iterator();
		while (it.hasNext()) {
			SymbolPanel panel = it.next();
			panel.dispose();
		}
		symProvider = null;
		symPanels = null;
		boxPanel = null;
		listScroller = null;
		this.removeAll();
	}
	
	GhidraTable getTable() {
		if (symPanels.size() > 0) {
			return symPanels.get(0).getTable();
		}
		return null;
	}
	
	List<GhidraTable> getAllTables() {
		List<GhidraTable> tableList = new ArrayList<>();
		Iterator<SymbolPanel> it = symPanels.iterator();
		while (it.hasNext()) {
			SymbolPanel panel = it.next();
			tableList.add(panel.getTable());
		}
		return tableList;
	}
	
	int getActualSymbolCount() {
		int count = 0;
		Iterator<SymbolPanel> it = symPanels.iterator();
		while (it.hasNext()) {
			SymbolPanel panel = it.next();
			count += panel.getModel().getRowCount();
		}
		return count;
	}
	
	void readConfigState(SaveState saveState) {
		Iterator<SymbolPanel> it = symPanels.iterator();
		while (it.hasNext()) {
			SymbolPanel panel = it.next();
			panel.readConfigState(saveState);
		}
	}
	
	void writeConfigState(SaveState saveState) {
		Iterator<SymbolPanel> it = symPanels.iterator();
		while (it.hasNext()) {
			SymbolPanel panel = it.next();
			panel.writeConfigState(saveState);
		}
	}
	
	NewSymbolFilter getFilter() {
		if (symPanels.size() > 0) {
			return symPanels.get(0).getFilter();
		}
		return null;
	}
	
	void setProgram(Program p) {
		program = p;
	}
	
	void clearOtherSelections(Namespace ns) {
		Iterator<SymbolPanel> it = symPanels.iterator();
		while (it.hasNext()) {
			SymbolPanel panel = it.next();
			Namespace iterNs = panel.getNamespace();
			if (!iterNs.equals(ns)) {
				panel.getTable().clearSelection();
			}
		}
	}
	
	Iterator<SymbolPanel> getPanels() { 
		return this.symPanels.iterator(); 
	}

	SymbolProvider getSymProvider() {
		return this.symProvider;
	}
	public void setTextFiltering(boolean set) {
		this.textFiltering = set; 
	}
	
	public Boolean isTextFiltering() {
		return this.textFiltering;
	}

}
