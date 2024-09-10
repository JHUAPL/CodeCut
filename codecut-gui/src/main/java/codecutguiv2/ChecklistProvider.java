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

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseEvent;
import java.util.HashMap;
import java.util.Set;
import java.util.Vector;

import javax.swing.AbstractButton;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.event.TableModelListener;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableModel;

import docking.ActionContext;
import docking.WindowPosition;
import ghidra.app.context.ProgramActionContext;
import ghidra.app.services.BlockModelService;
import ghidra.feature.vt.api.db.TableColumn;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.HelpLocation;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.GhidraTableCellRenderer;
import ghidra.util.table.GhidraThreadedTablePanel;
import graphcut.GraphCutProvider;
import resources.ResourceManager;

public class ChecklistProvider extends ComponentProviderAdapter implements ActionListener {
	
	private static final ImageIcon ICON = ResourceManager.loadImage("images/textfield.png");
	private static final String BUTTON_STRING = "Apply Changes";
	private static final String RESET_STRING = "Reset Graph Filter";
	
	private CodeCutGUIPlugin plugin;
	private GraphCutProvider graphProvider;
	GhidraTable table;
	DefaultTableModel model;
	
	private JPanel boxPanel;
	
	ChecklistProvider(CodeCutGUIPlugin plugin){
		super(plugin.getTool(), "Namespaces in Graph", plugin.getName(), ProgramActionContext.class);
		this.plugin = plugin;
		this.graphProvider = plugin.getGraphProvider();
		
		setIcon(ICON);
		addToToolbar();
		setHelpLocation(new HelpLocation(plugin.getName(), "CodeCut_Table"));
		setWindowGroup("codecutTable");
		setIntraGroupPosition(WindowPosition.BOTTOM);
		
		boxPanel = new JPanel();
		boxPanel.setLayout(new BoxLayout(boxPanel, BoxLayout.Y_AXIS));
			
		Object[] columnNames = {"Namespace", "Added to Graph"};
		Object[][] data = {};
		model = new DefaultTableModel(data, columnNames) {
			
			@Override
			public boolean isCellEditable(int row, int column) {
				if(column == 1) {
					return true;
				}
				return false;
			}
		};
		table = new GhidraTable(model) {
			@Override
			public Class getColumnClass(int column) {
				switch(column) {
					case 0:
						return Namespace.class;
					case 1:
						return Boolean.class;
					default:
						return String.class;
				}
			}	
		};
		table.getTableHeader().setReorderingAllowed(false);
		table.setPreferredScrollableViewportSize(table.getPreferredSize());
		table.setDefaultRenderer(Namespace.class, new DefaultTableCellRenderer() {
			@Override
			public void setValue(Object value) {
				setText(((Namespace) value).getName());
			}
		});
		JScrollPane scrollPane = new JScrollPane(table);
		boxPanel.add(scrollPane);
		boxPanel.setSize(boxPanel.getPreferredSize());
		
		
		JPanel buttonPane = new JPanel();
		
		JButton applyButton = new JButton(BUTTON_STRING);
		applyButton.setVerticalTextPosition(AbstractButton.CENTER);
		applyButton.setActionCommand(BUTTON_STRING);
		applyButton.addActionListener(this);
		
		JButton resetButton = new JButton(RESET_STRING);
		resetButton.setVerticalTextPosition(AbstractButton.CENTER);
		resetButton.setActionCommand(RESET_STRING);
		resetButton.addActionListener(this);
		
		buttonPane.setLayout(new BoxLayout(buttonPane, BoxLayout.LINE_AXIS));
		buttonPane.setBorder(BorderFactory.createEmptyBorder(0, 10, 10, 10));
		buttonPane.add(Box.createHorizontalGlue());
		buttonPane.add(applyButton);
		buttonPane.add(Box.createRigidArea(new Dimension(10, 0)));
		buttonPane.add(resetButton);
		boxPanel.add(buttonPane);
		
		setIntraGroupPosition(WindowPosition.RIGHT);
		buildTable();
	}
	
	void buildTable() {
		model.setRowCount(0);
		Set<Namespace>inGraph = graphProvider.getNamespacesInFilter();
		for(Namespace ns: inGraph) {
			model.addRow(new Object[]{ns, true});
		}
	}
	
	void dispose() {
		plugin = null;
	}
	
	@Override
	public void actionPerformed(ActionEvent e) {
		if(BUTTON_STRING.equals(e.getActionCommand())) {
			Vector<Vector> data = model.getDataVector();
			for(int i = 0; i < model.getRowCount(); i++) {
				Namespace victim = (Namespace)data.elementAt(i).elementAt(0);
				if(!(boolean)data.elementAt(i).elementAt(1)) {
					graphProvider.removeFromWhitelist(victim);
				}
			}
		}
		else if(RESET_STRING.equals(e.getActionCommand())) {
			graphProvider.resetWhitelist();
		}
		
		buildTable();
	}

	@Override
	public JComponent getComponent() {
		return boxPanel;
	}
	
	@Override
	public ActionContext getActionContext(MouseEvent event) {
		Program program = plugin.getProgram();
		if(program == null) {
			return null;
		}
		return new ProgramActionContext(this, program);
	}
	
	public void open() {
		if (!isVisible()) {
			setVisible(true);
		}
	}

}

