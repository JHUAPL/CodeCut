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


import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.MouseEvent;
import java.util.Arrays;
import java.util.List;

import javax.swing.AbstractButton;
import javax.swing.BoxLayout;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JTextField;

import docking.ActionContext;
import docking.WindowPosition;
import ghidra.app.context.ProgramActionContext;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.layout.PairLayout;
import resources.ResourceManager;

class CreateProvider extends ComponentProviderAdapter implements ActionListener {

	private static final ImageIcon ICON = ResourceManager.loadImage("images/textfield.png");

	private CodeCutGUIPlugin plugin;
	private JPanel boxPanel;
	private JTextField textField;
	private JButton button;

	private Namespace namespace;
	private Symbol symbol;

	CreateProvider(CodeCutGUIPlugin plugin) {
		super(plugin.getTool(), "Create Namespace", plugin.getName(), ProgramActionContext.class);
		this.plugin = plugin;

		setIcon(ICON);
		addToToolbar();
		setHelpLocation(new HelpLocation(plugin.getName(), "CodeCut_Table"));
		setWindowGroup("codecutTable");
		setIntraGroupPosition(WindowPosition.BOTTOM);

		boxPanel = new JPanel();
		boxPanel.setLayout(new BoxLayout(boxPanel, BoxLayout.Y_AXIS));
		
		JPanel entryPanel = new JPanel(new PairLayout(6,10));
		textField = new JTextField(30);
		if (namespace != null) {
			textField.setText(namespace.getName());
		}
		button = new JButton("Create Namespace");
		button.setVerticalTextPosition(AbstractButton.CENTER);
		button.setHorizontalTextPosition(AbstractButton.CENTER);
		button.setMnemonic(KeyEvent.VK_ENTER);
		button.setActionCommand("submit");
		button.addActionListener(this);
		entryPanel.add(textField);
		entryPanel.add(button);
		entryPanel.setSize(entryPanel.getPreferredSize().width, textField.getPreferredSize().height);
		Dimension dim = entryPanel.getPreferredSize();
		boxPanel.add(entryPanel);
		boxPanel.setSize(dim);
		setIntraGroupPosition(WindowPosition.RIGHT);

	}

	public void actionPerformed(ActionEvent e) {
		if (this.namespace != null) {
			if ("submit".equals(e.getActionCommand())) {
				String newNamespace = textField.getText();
				Program program = plugin.getProgram();
				SymbolTable symbolTable = program.getSymbolTable();
				if (CodecutUtils.getMatchingNamespaces(newNamespace, Arrays.asList(program.getGlobalNamespace()), program).isEmpty()) {
					Namespace nS=null;
					int transactionID = program.startTransaction("nsCreate");
					try {
						nS = symbolTable.createNameSpace(program.getGlobalNamespace(), newNamespace, SourceType.USER_DEFINED);
					}
					catch (DuplicateNameException ex) {
						//NS was already created, 
						List<Namespace> nL = CodecutUtils.getNamespacesByName(program, program.getGlobalNamespace(), newNamespace);
						if (nL == null) {
							return;
						}
						nS = nL.get(0);
					}
					catch (InvalidInputException ex) {
						program.endTransaction(transactionID, false);
						return;
					}
					program.endTransaction(transactionID, true);
					
					
					try {
						CodecutUtils.splitNamespace(program, this.symbol, nS);
					} catch (Exception ex) {
						Msg.info(this, "Exception when attempting to change namespace of symbol " 
								+ this.symbol.getName() + " to " + nS.getName());
					}
					
					this.closeComponent(); 

				}
			}
				
		}
		


	}
	
	void open() {
		if (!isVisible()) {
			setVisible(true);
		}
	}
	
	void dispose() {
		plugin = null;
	}
	
	public void setCurrentNamespace(Namespace ns) {
		this.namespace = ns;
		this.textField.setText(ns.getName());
	}
	
	public void setCurrentSymbol(Symbol symbol) {
		this.symbol = symbol;
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		Program program = plugin.getProgram();
		if (program == null) {
			return null;
		}
		return new ProgramActionContext(this, program);
	}

	public void updateTitle() {
		setSubTitle("Add to New Namespace");
	}

	@Override
	public JComponent getComponent() {
		return boxPanel;
	}
}
