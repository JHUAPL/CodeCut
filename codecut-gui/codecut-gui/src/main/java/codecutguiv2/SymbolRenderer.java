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

import java.awt.Color;
import java.awt.Component;

import docking.widgets.table.GTableCellRenderingData;
import ghidra.app.util.SymbolInspector;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.VariableNameFieldLocation;
import ghidra.util.table.GhidraTableCellRenderer;

class SymbolRenderer extends GhidraTableCellRenderer {
	private SymbolInspector inspector;

	SymbolRenderer() {
		super();
	}

	void setSymbolInspector(SymbolInspector inspector) {
		this.inspector = inspector;
	}

	@Override
	public Component getTableCellRendererComponent(GTableCellRenderingData data) {

		super.getTableCellRendererComponent(data);

		Object value = data.getValue();
		int column = data.getColumnModelIndex();
		boolean isSelected = data.isSelected();

		if (value == null && column == SymbolTableModel.LABEL_COL) {
			setText("<< REMOVED >>");
		}
		else if (value instanceof Symbol) {
			handleSymbol(value, isSelected);
		}
		else if (value instanceof Address) {
			setText(getAddressString((Address) value));
		}
		else if (value instanceof ProgramLocation) {
			setText(getLocationString((ProgramLocation) value));
		}

		return this;
	}

	private String getLocationString(ProgramLocation location) {
		if (location instanceof VariableNameFieldLocation) {
			VariableNameFieldLocation varLoc = (VariableNameFieldLocation) location;
			Variable variable = varLoc.getVariable();
			return variable.getVariableStorage().toString();
		}
		return getAddressString(location.getAddress());
	}

	private void handleSymbol(Object value, boolean isSelected) {
		setBold();
		Color color =
			(inspector != null) && (value instanceof Symbol) ? inspector.getColor((Symbol) value)
					: Color.BLACK;

		if (!isSelected) {
			setForeground(color);
		}
	}

	private String getAddressString(Address address) {
		if (address.isStackAddress()) {
			return getStackAddressString(address);
		}
		else if (address.isRegisterAddress()) {
			return getRegisterAddressString(address);
		}
		else if (address.isExternalAddress() || address == Address.NO_ADDRESS) {
			return "";
		}
		return address.toString();
	}

	private String getRegisterAddressString(Address address) {
		Program program = inspector.getProgram();
		if (program != null) {
			Register register = program.getRegister(address);
			if (register != null) {
				return register.toString();
			}
		}
		return "";
	}

	private String getStackAddressString(Address address) {
		long offset = address.getOffset();
		if (offset < 0) {
			return "Stack[-0x" + Long.toHexString(-offset) + "]";
		}
		return "Stack[0x" + Long.toHexString(offset) + "]";
	}

}
