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

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import ghidra.app.script.GhidraScriptLoadException;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.CircularDependencyException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Uses the DeepCut algorithm to find module boundaries.
 */
public class DeepCutAnalyzer extends AbstractAnalyzer {
    private static final String NAME = "Deepcut";
    private static final String DESCRIPTION = "Uses the deepcut algorithm to find module boundaries.";

    private final Gson gson = new GsonBuilder().create();

    public DeepCutAnalyzer() {
        super(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER);
        setDefaultEnablement(false);
        setPriority(AnalysisPriority.REFERENCE_ANALYSIS.after());
        setPrototype();
        setSupportsOneTimeAnalysis();
        
        Msg.info(this, "DeepCutAnalyzer loaded");
    }

    @Override
	public boolean getDefaultEnablement(Program program) {
		// Only supports one-time analysis.
		return false;
	}

	@Override
	public boolean canAnalyze(Program program) {
		return true;
	}

	@Override
	public void registerOptions(Options options, Program program) {
		// no options
	}
	
    @Override
    public void optionsChanged(Options options, Program program) {
            // no options
    }


    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
            throws CancelledException {

        
            // 1) Build input JSON from the program
            FunctionCallGraph fcg = new FunctionCallGraph(program, monitor);
            String inputJson = fcg.toJson();

            // 2) Run DeepCut via the launcher (blocking, file-IO args under the hood)
            String cutsJson="";
			try {
				cutsJson = DeepCutLauncher.runFileMode(program, set, inputJson, monitor);
			} catch (IllegalAccessException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (FileNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (GhidraScriptLoadException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
            if (cutsJson == null || cutsJson.isEmpty()) {
                log.appendMsg("DeepCut returned no output.");
                return false;
            }
            
        try {

            // 3) Parse result and apply namespaces
            Cut[] cuts = gson.fromJson(cutsJson, Cut[].class);
            int i = 0;

            for (FunctionInfo fi : fcg.getFunctionInfos()) {
                AddressFactory af = program.getAddressFactory();
                Address cutAddress = af.getAddress(cuts[i].address);

                if (fi.getAddress().compareTo(cutAddress) < 0) {
                    addNamespace(program, "object" + i, fi.getFunction());
                } else {
                    i++;
                    addNamespace(program, "object" + i, fi.getFunction());
                    if (i >= cuts.length) {
                        // no more cuts; remaining functions go into the last bucket
                        // (optional: break; if you prefer to stop assigning)
                        i = cuts.length - 1;
                    }
                }
            }
            return true;
        } catch (Exception e) {
            log.appendException(e);
            return false;
        }
    }

    private void addNamespace(Program program, String name, Function function)
            throws DuplicateNameException, InvalidInputException, CircularDependencyException {
        SymbolTable symbolTable = program.getSymbolTable();
        Namespace ns = symbolTable.getNamespace(name, null);
        if (ns == null) {
            ns = symbolTable.createNameSpace(null, name, SourceType.USER_DEFINED);
        }
        function.setParentNamespace(ns);
    }
}