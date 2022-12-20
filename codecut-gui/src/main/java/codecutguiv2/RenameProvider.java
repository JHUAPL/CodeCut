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
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.layout.PairLayout;
import resources.ResourceManager;

class RenameProvider extends ComponentProviderAdapter implements ActionListener {

	private static final ImageIcon ICON = ResourceManager.loadImage("images/textfield.png");

	private CodeCutGUIPlugin plugin;
	private JPanel boxPanel;
	private JTextField textField;
	private JButton button;

	private Namespace namespace;

	RenameProvider(CodeCutGUIPlugin plugin) {
		super(plugin.getTool(), "Rename Namespace", plugin.getName(), ProgramActionContext.class);
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
		button = new JButton("Rename");
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
	
		//addToTool();
	}

	public void actionPerformed(ActionEvent e) {
		if (this.namespace != null) {
			if ("submit".equals(e.getActionCommand())) {
				String newNamespace = textField.getText();
				Program program = plugin.getProgram();
				SymbolTable symbolTable = program.getSymbolTable();
				if (CodecutUtils.getMatchingNamespaces(newNamespace, Arrays.asList(program.getGlobalNamespace()), program).isEmpty()) {
					Namespace nS=null;
					int transactionID = program.startTransaction("ns");
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
					
					
					//rename all symbols in same module to new NS
					try {
						CodecutUtils.renameNamespace(program, namespace, nS);
						Msg.info(this, "Namespace " + namespace.getName() + " renamed to " + nS.getName());
					} catch (Exception ex) {
						Msg.info(this, "Exception when renaming namespace " + namespace.getName() + ": " + ex.getMessage());
						
					}
					this.closeComponent(); 

				}
				else { 
					Namespace nS = symbolTable.getNamespace(newNamespace, program.getGlobalNamespace());
					if (symbolTable.getSymbols(nS).hasNext()) {
						throw new IllegalArgumentException("Namespace already exists"); 
					}
					else { 
						CodecutUtils.setUpdating(true);
						SymbolIterator iter = symbolTable.getSymbols(namespace);
						Symbol currSym = null;
						int transactionID = program.startTransaction("nsRename");
						try {
							while (iter.hasNext()) {
								currSym = iter.next();
								currSym.setNamespace(nS);
							}
							namespace.getSymbol().delete();
						}
						catch (Exception exception) {
							Msg.info(new Object(), "Could not set namespace for " + currSym.getName());
							Msg.info(new Object(), exception.getMessage());
							program.endTransaction(transactionID, false);
						}
						program.endTransaction(transactionID, true);
						CodecutUtils.setUpdating(false);
						this.closeComponent(); 
					}
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

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		Program program = plugin.getProgram();
		if (program == null) {
			return null;
		}
		return new ProgramActionContext(this, program);
	}

	public void updateTitle() {
		setSubTitle("Rename Namespace");
	}

	@Override
	public JComponent getComponent() {
		return boxPanel;
	}
}
