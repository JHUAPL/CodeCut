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

import java.awt.datatransfer.*;

import javax.swing.*;

import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;
import ghidra.util.table.*;

public class CodeCutTransferHandler extends TransferHandler {

	public boolean canImport(TransferHandler.TransferSupport support) {
	    if (!support.isDrop()) {
	        return false;
	    }

	    if (!support.isDataFlavorSupported(DataFlavor.stringFlavor)) {
	        return false;
	    }
	    return true;
	}
	
	protected Transferable createTransferable(JComponent c) {
		CodecutUtils.setTransferring(true);
		GhidraTable table = (GhidraTable)c;
		SymbolTableModel model = (SymbolTableModel)table.getModel();
		int selectedRow = table.getSelectedRow();
		Symbol sym = model.getRowObject(selectedRow); // will this work if order is changed in UI?
		Msg.info(this, "DnD createTransferable - selected symbol is " + sym.getName());
		
		StringBuffer buff = new StringBuffer();
		String[] path = sym.getPath();
		Msg.info(this, "Symbol path is: " + path);
		buff.append(sym.getName());
		buff.append(",");
		buff.append(sym.getAddress());
		buff.append(",");
		buff.append(selectedRow);
		buff.append(",");
		buff.append(sym.getID());
		Msg.info(this, "DnD export: " + buff.toString());
		return new StringSelection(buff.toString());
	}
	
	public int getSourceActions(JComponent c) {
		return TransferHandler.COPY_OR_MOVE;
	}
	
	public boolean importData(TransferHandler.TransferSupport info) {
		Msg.info(this, "in transfer handler's importData");
		if (!info.isDrop()) {
			return false;
		}
		
		Transferable t = info.getTransferable();
		String data;
		try {
			data = (String)t.getTransferData(DataFlavor.stringFlavor);
		}
		catch (Exception e) {
			return false;
		}
		
		String[] values = data.split(",");
		if (values.length == 4) {
			GhidraTable table = (GhidraTable)info.getComponent();
			SymbolTableModel model = (SymbolTableModel)table.getModel();
			SymbolTable symTable = model.getProgram().getSymbolTable();
			
			long symId = Long.parseLong(values[3]);
			Symbol symToUpdate = symTable.getSymbol(symId);
			
					
			Namespace targetNs = model.getRowObject(0).getParentNamespace();
			Msg.info(this, "Updating " + symToUpdate.getName() + " to ns " + targetNs.getName());
			int transactionID = table.getProgram().startTransaction("ns");
			try {
				symToUpdate.setNamespace(targetNs);
			}
			catch (Exception e) {
				Msg.info(this, "Could not change symbol " + symToUpdate.getName() + " to namespace " + targetNs + " in DnD operation - " + e.getClass() + ": " + e.getMessage());
				table.getProgram().endTransaction(transactionID, false);
			}
			table.getProgram().endTransaction(transactionID, true);
			
			return true;
		}
		return false;
		
	}
}
