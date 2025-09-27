package codecutguiv2;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

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

/**
 * Base class for launching PyGhidra scripts in "file mode":
 *   - writes input payload to a temp infile
 *   - runs a named script with args [infile, outfile, ...extraArgs]
 *   - reads output payload from the outfile
 *
 * Subclasses override:
 *   - script name
 *   - temp file prefixes/suffixes (optional)
 *   - extra args (optional)
 *   - UI strings for error dialogs (optional)
 */
public abstract class PyGhidraFileLauncher {

    /** Provide the script file name that must be on the Ghidra script path. */
    protected abstract String getScriptName();

    /** Prefix for the temp input file (default: "in_"). */
    protected String getInfilePrefix() { return "in_"; }
    /** Suffix/extension for the temp input file (default: ".json"). */
    protected String getInfileSuffix() { return ".json"; }

    /** Prefix for the temp output file (default: "out_"). */
    protected String getOutfilePrefix() { return "out_"; }
    /** Suffix/extension for the temp output file (default: ".json"). */
    protected String getOutfileSuffix() { return ".json"; }

    /** 
     * Return any extra script args after [infile, outfile]. Default: none. 
     * If this is used, the subclass must be defined in its own .java file
     * in order for Ghidra the correctly find the module data file
     * (yes this is strange)
     */
    protected String[] getExtraArgs(PluginTool tool) throws Exception { return new String[0]; }

    /** Title and message for the “PyGhidra required” dialog. */
    protected String getLaunchFailDialogTitle() { return "Script Failed to Launch"; }
    protected String getLaunchFailDialogBodyPrefix() { return "This feature requires the PyGhidra extension.\n\nDetails: "; }

    /**
     * Run the script synchronously and return the outfile contents (trimmed), or null on cancel/error.
     */
    public String runFileMode(Program program,
                              AddressSetView set,
                              String inputPayload,
                              TaskMonitor monitor)
            throws IllegalAccessException, FileNotFoundException, GhidraScriptLoadException {

        final String scriptName = getScriptName();

        AutoAnalysisManager aam = AutoAnalysisManager.getAnalysisManager(program);
        PluginTool tool = aam.getAnalysisTool();
        Project project = tool != null ? tool.getProject() : null;
        
        Msg.info(getClass(), "tool: " + tool.getName());

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
        
        Msg.info(getClass(), "Chosen provider: " + provider.getClass().getName() +
                "  (runtime=" + provider.getRuntimeEnvironmentName() + ")");

        GhidraScript script;
        try {
            script = provider.getScriptInstance(sourceFile, err);
        } catch (GhidraScriptLoadException e) {
            ghidra.util.Msg.showError(
                    null, null,
                    getLaunchFailDialogTitle(),
                    getLaunchFailDialogBodyPrefix() + e.getMessage()
            );
            throw e;
        }

        try {
            // 2) Prep temp files
            inFile  = Files.createTempFile(getInfilePrefix(),  getInfileSuffix());
            outFile = Files.createTempFile(getOutfilePrefix(), getOutfileSuffix());
            inFile.toFile().deleteOnExit();
            outFile.toFile().deleteOnExit();

            // write input payload
            Files.writeString(inFile, (inputPayload == null ? "" : inputPayload) + "\n", StandardCharsets.UTF_8);

            // 3) Assemble args: [infile, outfile, ...extra]
            String[] extras = getExtraArgs(tool);
            String[] args = new String[2 + extras.length];
            args[0] = inFile.toString();
            args[1] = outFile.toString();
            System.arraycopy(extras, 0, args, 2, extras.length);
            script.setScriptArgs(args);

            // 4) Run blocking
            script.execute(state, monitor, out);

            // 5) Read result payload
            return Files.readString(outFile, StandardCharsets.UTF_8).trim();
        }
        catch (CancelledException e) {
            return null;
        }
        catch (Exception e) {
            Msg.warn(getClass(), "Error running script " + scriptName + ": " + e.getMessage(), e);
            return null;
        }
        finally {
            try { if (inFile  != null) Files.deleteIfExists(inFile);  } catch (IOException ignored) {}
            try { if (outFile != null) Files.deleteIfExists(outFile); } catch (IOException ignored) {}
        }
    }

    // ----- console helpers -----
    protected static PrintWriter getOut(PluginTool tool) {
        if (tool != null) {
            ConsoleService console = tool.getService(ConsoleService.class);
            if (console != null) return console.getStdOut();
        }
        return new PrintWriter(System.out);
    }

    protected static PrintWriter getErr(PluginTool tool) {
        if (tool != null) {
            ConsoleService console = tool.getService(ConsoleService.class);
            if (console != null) return console.getStdErr();
        }
        return new PrintWriter(System.err);
    }
}
