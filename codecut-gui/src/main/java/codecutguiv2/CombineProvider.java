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
import javax.swing.JLabel;
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

class CombineProvider extends ComponentProviderAdapter implements ActionListener {

	private static final ImageIcon ICON = ResourceManager.loadImage("images/textfield.png");

	private CodeCutGUIPlugin plugin;
	private JPanel boxPanel;
	private JTextField firstTextField;
	private JTextField secondTextField;
	private JTextField combinedTextField; 
	private JButton button;

	private Namespace firstNamespace;
	private Namespace secondNamespace;
	private Namespace combinedNamespace; 

	CombineProvider(CodeCutGUIPlugin plugin) {
		super(plugin.getTool(), "Combine Namespaces", plugin.getName(), ProgramActionContext.class);
		this.plugin = plugin;

		setIcon(ICON);
		addToToolbar();
		setHelpLocation(new HelpLocation(plugin.getName(), "CodeCut_Table"));
		setWindowGroup("codecutTable");
		setIntraGroupPosition(WindowPosition.BOTTOM);

		boxPanel = new JPanel();
		boxPanel.setLayout(new BoxLayout(boxPanel, BoxLayout.Y_AXIS));
		
		JPanel entryPanel = new JPanel(new PairLayout(6,10));
		
		JLabel firstLabel = new JLabel("Primary Namespace: ");
		JLabel secondLabel = new JLabel("Secondary Namespace: ");
		JLabel combinedLabel = new JLabel("Combined Namespace: ");
		
		firstTextField = new JTextField(30);
		if (firstNamespace != null) {
			firstTextField.setText(firstNamespace.getName());
		}
		secondTextField = new JTextField(30);
		if (secondNamespace != null) {
			secondTextField.setText(secondNamespace.getName());
		}
		combinedTextField = new JTextField(30); 
		if (combinedNamespace != null) {
			combinedTextField.setText(combinedNamespace.getName()); 
		}
		button = new JButton("Combine");
		button.setVerticalTextPosition(AbstractButton.CENTER);
		button.setHorizontalTextPosition(AbstractButton.CENTER);
		button.setMnemonic(KeyEvent.VK_ENTER);
		button.setActionCommand("submit");
		button.addActionListener(this);
		entryPanel.add(firstLabel);
		entryPanel.add(firstTextField);
		entryPanel.add(secondLabel);
		entryPanel.add(secondTextField);
		entryPanel.add(combinedLabel);
		entryPanel.add(combinedTextField); 
		entryPanel.add(button);
		entryPanel.setSize(entryPanel.getPreferredSize().width, firstTextField.getPreferredSize().height);
		Dimension dim = entryPanel.getPreferredSize();
		boxPanel.add(entryPanel);
		boxPanel.setSize(dim);
		setIntraGroupPosition(WindowPosition.RIGHT);

	}

	public void actionPerformed(ActionEvent e) {
		if (this.firstNamespace != null) {
			// update first namespace if user changed the text field
			String firstName = this.firstTextField.getText();
			if (!this.firstNamespace.getName().equals(firstName)) {
				List<Namespace> nL = CodecutUtils.getNamespacesByName(plugin.getProgram(), null, firstName);
				if (nL.size() > 0) {
					this.firstNamespace = nL.get(0);
				}
			}
			
			// look up second namespace by name 
			String secondName = secondTextField.getText();
			List<Namespace> nL = CodecutUtils.getNamespacesByName(plugin.getProgram(), null, secondName);
			if (nL.size() > 0) {
				this.secondNamespace = nL.get(0);
			}
		}
		
		if (this.firstNamespace != null && this.secondNamespace != null) {
			if ("submit".equals(e.getActionCommand())) {
				Program program = plugin.getProgram();
				SymbolTable symbolTable = program.getSymbolTable();
				String newNamespace = combinedTextField.getText(); 
				if (CodecutUtils.getMatchingNamespaces(newNamespace, Arrays.asList(program.getGlobalNamespace()), program).isEmpty()) {
					Namespace nS = null;
					int transactionID = program.startTransaction("nsCombine");
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
						return;
					}
					finally {
						program.endTransaction(transactionID, true);
					}
					try {
						// Set the namespaces of all the symbols from namespaces to be combined
						CodecutUtils.renameNamespace(program, this.secondNamespace, nS);
						CodecutUtils.renameNamespace(program, this.firstNamespace, nS); 
						Msg.info(this, "Namespace " + this.secondNamespace.getName() + " combined with " + this.firstNamespace.getName() + " into namespace " + newNamespace);
					} catch (Exception ex) {
						Msg.info(this, "Exception when combining namespace " + this.secondNamespace.getName() + " with " +
									this.firstNamespace.getName() + ": " + ex.getMessage());
					}
					
				}
				else { 
					Namespace nS = symbolTable.getNamespace(newNamespace, program.getGlobalNamespace());
					int transactionID = program.startTransaction("nsCombine");

					// if namespace is empty 
					if (!symbolTable.getSymbols(nS).hasNext()) {
						try { 
							CodecutUtils.renameNamespace(program, this.secondNamespace, nS);
							CodecutUtils.renameNamespace(program, this.firstNamespace, nS); 
							Msg.info(this, "Namespace " + this.secondNamespace.getName() + " combined with " + this.firstNamespace.getName() + " into namespace " + newNamespace);
						} catch (Exception ex) {
							Msg.info(this, "Exception when combining namespace " + this.secondNamespace.getName() + " with " +
										this.firstNamespace.getName() + ": " + ex.getMessage());
						}
					}
					// if namespace is not empty 
					else { 
						if (nS == this.firstNamespace) {
							SymbolIterator iter = symbolTable.getSymbols(this.secondNamespace);
							Symbol currSym = null;
							try {
								while (iter.hasNext()) {
									currSym = iter.next();
									currSym.setNamespace(this.firstNamespace);
								}
								this.secondNamespace.getSymbol().delete();
							}
							catch (Exception exception) {
								Msg.info(new Object(), "Could not set namespace for " + currSym.getName());
								Msg.info(new Object(), exception.getMessage());
							}
						}
						else if (nS == this.secondNamespace) {
							SymbolIterator iter = symbolTable.getSymbols(this.firstNamespace);
							Symbol currSym = null;
							try {
								while (iter.hasNext()) {
									currSym = iter.next();
									currSym.setNamespace(this.secondNamespace);
								}
								this.firstNamespace.getSymbol().delete();
							}
							catch (Exception exception) {
								Msg.info(new Object(), "Could not set namespace for " + currSym.getName());
								Msg.info(new Object(), exception.getMessage());
							}
						}
						else { 
							throw new IllegalArgumentException("Combined Namespace entered already exists and is not part of current operation"); 
						}
						program.endTransaction(transactionID, true);
						
					}
				}

			}
		}
		
		this.closeComponent();
		


	}
	
	void open() {
		if (!isVisible()) {
			setVisible(true);
		}
	}
	
	void dispose() {
		plugin = null;
	}
	
	public void setFirstNamespace(Namespace ns) {
		this.firstNamespace = ns;
		this.firstTextField.setText(ns.getName());
	}
	
	public void setSecondNamespace(Namespace ns) {
		this.secondNamespace = ns;
		this.secondTextField.setText(ns.getName());
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
		setSubTitle("Combine Namespaces");
	}

	@Override
	public JComponent getComponent() {
		return boxPanel;
	}
}
