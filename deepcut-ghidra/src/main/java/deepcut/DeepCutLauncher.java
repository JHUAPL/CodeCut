package deepcut;

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
