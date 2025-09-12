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

package deepcut;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import ghidra.util.Msg;

import generic.jar.ResourceFile;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraScriptLoadException;
import ghidra.app.script.GhidraScriptProvider;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.script.GhidraState;
import ghidra.app.services.ConsoleService;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.framework.Application;

public class DeepCutLauncher {

    /**
     * Runs DeepCutRun.py synchronously with two args: infile and outfile.
     * Writes the provided JSON string to a temp infile, runs the script, reads the temp outfile,
     * and returns its contents. Best-effort temp cleanup.
     * @throws IllegalAccessException
     * @throws FileNotFoundException 
     */
    public static String runDeepCutFileMode(Program program,
                                            AddressSetView set,
                                            String inputJson,
                                            TaskMonitor monitor) throws IllegalAccessException, FileNotFoundException, GhidraScriptLoadException {
        final String scriptName = "DeepCutRun.py"; // must be on Ghidra script path

        AutoAnalysisManager aam = AutoAnalysisManager.getAnalysisManager(program);
        PluginTool tool = aam.getAnalysisTool();
        Project project = tool != null ? tool.getProject() : null;

        GhidraState state = new GhidraState(
                tool,
                project,
                program,
                new ProgramLocation(program, set.getMinAddress()),
                new ProgramSelection(set),
                null
        );

        PrintWriter out = getOut(tool);
        PrintWriter err = getErr(tool);

        Path inFile = null, outFile = null;
            // 1) Locate script
            ResourceFile sourceFile = GhidraScriptUtil.findScriptByName(scriptName);
            if (sourceFile == null) {
                throw new IllegalAccessException("Couldn't find script: " + scriptName);
            }
            GhidraScriptProvider provider = GhidraScriptUtil.getProvider(sourceFile);
            if (provider == null) {
                throw new IllegalAccessException("Couldn't find script provider for: " + scriptName);
            }
            ResourceFile pythonFile = Application.getModuleDataFile("model_weights.p");
            if (pythonFile == null) {
                throw new IllegalAccessException("Couldn't find weights file for: " + scriptName);
            }
            

            Msg.info(DeepCutLauncher.class, "Chosen provider: " + provider.getClass().getName() + "  (runtime=" + provider.getRuntimeEnvironmentName() + ")");
            
            GhidraScript script;
            try {
            	script = provider.getScriptInstance(sourceFile, err);
            }
            catch(GhidraScriptLoadException e) {
            	Msg.showError(
            	        null,                      // parent object (your plugin/analyzer/launcher)
            	        null,                      // parent component (null = center on tool)
            	        "PyGhidra Required",       // dialog title
            	        "DeepCut requires the PyGhidra extension.\n\nDetails: " + e.getMessage()
            	    );
            	    throw new GhidraScriptLoadException("DeepCut requires PyGhidra", e);
            }
            
             
 
            try {

            // 2) Prep temp files
            inFile  = Files.createTempFile("deepcut_in_",  ".json");
            outFile = Files.createTempFile("deepcut_out_", ".json");
            // ensure delete on JVM exit as a fallback
            inFile.toFile().deleteOnExit();
            outFile.toFile().deleteOnExit();

            // write input JSON
            Files.writeString(inFile, (inputJson == null ? "" : inputJson) + "\n", StandardCharsets.UTF_8);

            // 3) Pass args: [infile, outfile, modelfile]
            script.setScriptArgs(new String[] {
            		inFile.toString(),
            		outFile.toString(),
            		pythonFile.toString() });
            
            

            // 4) Run blocking
            script.execute(state, monitor, out);

            // 5) Read result JSON
            String result = Files.readString(outFile, StandardCharsets.UTF_8).trim();
            return result;
        }
        catch (CancelledException e) {
            // user cancelled; return null or empty to signal no result
            return null;
        }
        catch (Exception e) {
            Msg.warn(DeepCutLauncher.class, "Error running script " + scriptName + ": " + e.getMessage(), e);
            return null;
        }
        finally {
            // best-effort cleanup
            try { if (inFile  != null) Files.deleteIfExists(inFile);  } catch (IOException ignored) {}
            try { if (outFile != null) Files.deleteIfExists(outFile); } catch (IOException ignored) {}
        }
    }
    
    private static PrintWriter getOut(PluginTool tool) {
        if (tool != null) {
            ConsoleService console = tool.getService(ConsoleService.class);
            if (console != null) return console.getStdOut();
        }
        return new PrintWriter(System.out);
    }

    private static PrintWriter getErr(PluginTool tool) {
        if (tool != null) {
            ConsoleService console = tool.getService(ConsoleService.class);
            if (console != null) return console.getStdErr();
        }
        return new PrintWriter(System.err);
    }
}
