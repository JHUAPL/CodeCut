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

/*
 * Heavily Borrows from Ghidra file /Features Graph FunctionCalls/src/main/java/functioncalls/graph/renderer/FcgTooltipProvider.java
 */


package graphcut;

import java.awt.Component;
import java.awt.event.MouseEvent;

import javax.swing.JComponent;
import javax.swing.*;

import ghidra.graph.viewer.event.mouse.VertexTooltipProvider;

public class GraphCutTooltipProvider implements VertexTooltipProvider<GraphCutVertex, GraphCutEdge> {

	@Override
	public JComponent getTooltip(GraphCutVertex v) {
		JToolTip tip = new JToolTip();
		tip.setTipText(v.getName());
		return tip;
	}

	@Override
	public JComponent getTooltip(GraphCutVertex v, GraphCutEdge e) {
		return null;
	}

	@Override
	public String getTooltipText(GraphCutVertex v, MouseEvent e) {
		Component child  = e.getComponent();
		if(child instanceof JButton) {
			return ((JButton) child).getToolTipText();
		}
		return v.getName();
	}

}
