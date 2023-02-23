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

import java.util.ArrayList;
import java.util.List;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.RowFilter;
import javax.swing.border.BevelBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;

import docking.DockingWindowManager;
import docking.widgets.EmptyBorderButton;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.filter.FilterOptions;
import docking.widgets.filter.FilterOptionsEditorDialog;
import docking.widgets.filter.TextFilterStrategy;
import docking.widgets.label.GLabel;
import ghidra.util.table.GhidraTable;

@SuppressWarnings("serial")
public class CCTableFilterPanel extends JPanel {
	
	private List<TableRowSorter<TableModel>> sorters = new ArrayList<>(); 
	JTextField textField; 
	private SymbolProvider symProvider; 
	private NamespacePanel nsPanel; 
	private FilterOptions filterOptions = new FilterOptions(); 
	private EmptyBorderButton filterStateButton;
	private static final boolean FILTER_NAME_ONLY_DEFAULT = true;
	private boolean nameOnly = true;

	
	public CCTableFilterPanel (List<GhidraTable> tables, SymbolProvider symProvider, NamespacePanel panel) {
		this.symProvider = symProvider;
		this.nsPanel = panel; 
		for (GhidraTable table: tables) {
			TableRowSorter<TableModel> sort = new TableRowSorter<>(table.getModel());
			sorters.add(sort);
			table.setRowSorter(sort);
		}
		textField = new JTextField(); 
		buildPanel(); 
	}
	 public void buildPanel(){
		this.setLayout(new BoxLayout(this, BoxLayout.X_AXIS));
		this.setBorder(BorderFactory.createBevelBorder(BevelBorder.LOWERED));
		this.add(Box.createHorizontalStrut(5));
        this.add(new GLabel("Filter:"));
        this.add(textField);
        textField.getDocument().addDocumentListener(new DocumentListener()
	    {
            @Override
            public void insertUpdate(DocumentEvent e) {
                String str = textField.getText();
                if (str.trim().length() == 0) {
                	nsPanel.setTextFiltering(false);
                	for (TableRowSorter<TableModel> sort: sorters) {
                		sort.setRowFilter(null);
                	}
                } else {
                	nsPanel.setTextFiltering(true);
                	String filterRegex = generateFilterRegex(filterOptions.getTextFilterStrategy(), filterOptions.isCaseSensitive(), str); 
                	for (TableRowSorter<TableModel> sort: sorters) {
                		if (nameOnly) {
                			sort.setRowFilter(RowFilter.regexFilter(filterRegex, 0));
                		}
                		else {
                			sort.setRowFilter(RowFilter.regexFilter(filterRegex));
                		}
                	}
                }
                symProvider.updateTitle(); 
            }
            @Override
            public void removeUpdate(DocumentEvent e) {
                String str = textField.getText();
                if (str.trim().length() == 0) {
                	nsPanel.setTextFiltering(false);
                	for (TableRowSorter<TableModel> sort: sorters) {
                		sort.setRowFilter(null);
                	}
                } else {
                	nsPanel.setTextFiltering(true);
                	String filterRegex = generateFilterRegex(filterOptions.getTextFilterStrategy(), filterOptions.isCaseSensitive(), str); 
                	for (TableRowSorter<TableModel> sort: sorters) {
                		if (nameOnly) {
                			sort.setRowFilter(RowFilter.regexFilter(filterRegex, 0));
                		}
                		else {
                			sort.setRowFilter(RowFilter.regexFilter(filterRegex));
                		}
                	}
                }
                symProvider.updateTitle(); 
            }
            @Override
            public void changedUpdate(DocumentEvent e) {}
        });
        this.add(buildFilterStateButton());
        
        final JCheckBox nameColumnOnlyCheckbox = new GCheckBox("Name Only");
		nameColumnOnlyCheckbox.setName("NameOnly"); // used by JUnit
		nameColumnOnlyCheckbox.setToolTipText(
			"<html><b>Selected</b> causes filter to only consider the symbol's name.");
		nameColumnOnlyCheckbox.setFocusable(false);
		nameColumnOnlyCheckbox.setSelected(FILTER_NAME_ONLY_DEFAULT);
		nameColumnOnlyCheckbox.addItemListener(e -> {
			nameOnly = nameColumnOnlyCheckbox.isSelected();
		});

		this.add(nameColumnOnlyCheckbox);
	 }

	 private JComponent buildFilterStateButton() {
			filterStateButton = new EmptyBorderButton(filterOptions.getFilterStateIcon());
			filterStateButton.addActionListener(e -> {
				FilterOptionsEditorDialog dialog = new FilterOptionsEditorDialog(filterOptions);
				DockingWindowManager.showDialog(this, dialog);
				FilterOptions resultFilterOptions = dialog.getResultFilterOptions();
				if (resultFilterOptions != null) {
					this.filterOptions = resultFilterOptions;
				}
			});

			filterStateButton.setToolTipText("Filter Options");
			updateFilterFactory();
			return filterStateButton;
		}
	 
	 private void updateFilterFactory() {
			filterStateButton.setIcon(filterOptions.getFilterStateIcon());
			filterStateButton.setToolTipText(filterOptions.getFilterDescription());
	}
	
	private String generateFilterRegex(TextFilterStrategy type, Boolean isCaseSensitive, String input) {
		String caseSensitivity = ""; 
		if (!isCaseSensitive) {
			caseSensitivity = "(?i)"; 
		}
		if (filterOptions.getTextFilterStrategy() == TextFilterStrategy.STARTS_WITH) {
			return caseSensitivity + "^" + input; 
		}
		else if (filterOptions.getTextFilterStrategy() == TextFilterStrategy.CONTAINS) {
			return caseSensitivity + ".*" + input + ".*";
		}
		else if (filterOptions.getTextFilterStrategy() == TextFilterStrategy.MATCHES_EXACTLY) {
			return "^" + input; 								// no case insensitivity 
		}
		else {
			return input; 
		}
	}
}
