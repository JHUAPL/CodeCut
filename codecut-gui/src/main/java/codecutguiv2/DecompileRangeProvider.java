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
package codecutguiv2;


import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.MouseEvent;

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
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.layout.PairLayout;
import resources.ResourceManager;


class DecompileRangeProvider extends ComponentProviderAdapter implements ActionListener {

	private static final ImageIcon ICON = ResourceManager.loadImage("images/textfield.png");

	private CodeCutGUIPlugin plugin;
	private JPanel boxPanel;
	private JTextField firstTextField;
	private JTextField secondTextField;
	private JButton button;

	private String startAddr;
	private String endAddr;
	private Function func; 

	DecompileRangeProvider(CodeCutGUIPlugin plugin) {
		super(plugin.getTool(), "Decompile Range", plugin.getName(), ProgramActionContext.class);
		this.plugin = plugin;

		setIcon(ICON);
		addToToolbar();
		setHelpLocation(new HelpLocation(plugin.getName(), "CodeCut_Table"));
		setWindowGroup("codecutTable");
		setIntraGroupPosition(WindowPosition.BOTTOM);

		boxPanel = new JPanel();
		boxPanel.setLayout(new BoxLayout(boxPanel, BoxLayout.Y_AXIS));
		
		JPanel entryPanel = new JPanel(new PairLayout(6,10));
		
		JLabel firstLabel = new JLabel("Starting Address: ");
		JLabel secondLabel = new JLabel("Ending Address: ");
		
		firstTextField = new JTextField(30);
		if (this.startAddr != null) {
			firstTextField.setText(this.startAddr);
		}
		secondTextField = new JTextField(30);
		if (this.endAddr != null) {
			secondTextField.setText(this.endAddr);
		}
		
		button = new JButton("Decompile Range");
		button.setVerticalTextPosition(AbstractButton.CENTER);
		button.setHorizontalTextPosition(AbstractButton.CENTER);
		button.setMnemonic(KeyEvent.VK_ENTER);
		button.setActionCommand("submit");
		button.addActionListener(this);
		entryPanel.add(firstLabel);
		entryPanel.add(firstTextField);
		entryPanel.add(secondLabel);
		entryPanel.add(secondTextField);
		entryPanel.add(button);
		entryPanel.setSize(entryPanel.getPreferredSize().width, firstTextField.getPreferredSize().height);
		Dimension dim = entryPanel.getPreferredSize();
		boxPanel.add(entryPanel);
		boxPanel.setSize(dim);
	
	}

	public void actionPerformed(ActionEvent e) {
		if (this.startAddr == null) {
			this.startAddr = firstTextField.getText();
			this.endAddr = secondTextField.getText();
			//the right thing to do here would be to try to convert to Address
			//and throw an error if that doesn't work
		}
		
		if (this.startAddr != null && this.endAddr != null) {
			if ("submit".equals(e.getActionCommand())) {
				Program program = plugin.getProgram();
				plugin.exportC(startAddr, endAddr); 
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
	
	public void setFunc(Address addr) {
		this.func = plugin.getProgram().getFunctionManager().getFunctionAt(addr); 
		firstTextField.setText(func.getEntryPoint().toString());
		secondTextField.setText(getFnEndAddr(func.getEntryPoint()).toString());
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
		setSubTitle("Decompile Range");
	}

	protected Address getFnEndAddr(Address start) {
		FunctionManager fm = plugin.getProgram().getFunctionManager(); 
		Function fn = fm.getFunctionAt(start);
		FlatProgramAPI fp = new FlatProgramAPI(plugin.getProgram()); 
		return fp.getFunctionAfter(fn).getEntryPoint(); 
	}
	
	@Override
	public JComponent getComponent() {
		return boxPanel;
	}
}
