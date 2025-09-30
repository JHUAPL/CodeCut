package deepcut;

/*
 * © 2025 The Johns Hopkins University Applied Physics Laboratory LLC (JHU/APL).  
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

import java.io.FileNotFoundException;

import generic.jar.ResourceFile;
import ghidra.app.script.GhidraScriptLoadException;
import ghidra.framework.Application;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public class DeepCutLauncher extends PyGhidraFileLauncher {

    @Override protected String getScriptName() { return "DeepCutRun.py"; }
    @Override protected String getInfilePrefix() { return "deepcut_in"; }
    @Override protected String getOutfilePrefix() { return "deepcut_out"; }
    @Override protected String getInfileSuffix() { return ".json"; }
    @Override protected String getOutfileSuffix() { return ".json"; }

    @Override
    protected String[] getExtraArgs(ghidra.framework.plugintool.PluginTool tool) throws Exception {
        
    	// derive the correct module name at runtime
    	String moduleName = Application.getMyModuleRootDirectory().getName();
	
    	// Locate model weights packaged with the extension/module
    	ResourceFile weights = Application.getModuleDataFile(moduleName, "model_weights.p");
        if (weights == null) {
            throw new IllegalAccessException("Couldn't find weights file for: " + getScriptName());
        }
        return new String[] { weights.toString() };
    }

    // Convenience static method to preserve your old call-site signature
    public static String execute(Program program,
                                     AddressSetView set,
                                     String inputPayload,
                                     TaskMonitor monitor)
            throws IllegalAccessException, FileNotFoundException, GhidraScriptLoadException {
        return new DeepCutLauncher().runFileMode(program, set, inputPayload, monitor);
    }

    @Override protected String getLaunchFailDialogTitle() { return "DeepCut Failed to Launch"; }
    @Override protected String getLaunchFailDialogBodyPrefix() {
        return "DeepCut requires the PyGhidra extension.\n\nDetails: ";
    }
}
