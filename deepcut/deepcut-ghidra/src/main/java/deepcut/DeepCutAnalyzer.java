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

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.ElfLoader;
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
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

import com.google.gson.GsonBuilder;

/**
 * TODO: Provide class-level documentation that describes what this analyzer does.
 */
public class DeepCutAnalyzer extends AbstractAnalyzer {
	private final static String NAME = "Deepcut";
	private final static String DESCRIPTION = "Uses the deepcut algorithm to find module boundaries.";
	
	private final static String OPTION_NAME_PYTHON_EXEC = "Python Executable";
	private final static String OPTION_DESCRIPTION_PYTHON_EXEC = "";
	private final static String OPTION_DEFAULT_PYTHON_EXEC = "/projects/venv/bin/python3";
	private String pythonExec = OPTION_DEFAULT_PYTHON_EXEC;

	public DeepCutAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER);
		setDefaultEnablement(false);
		setPriority(AnalysisPriority.REFERENCE_ANALYSIS.after());
		setPrototype();
		setSupportsOneTimeAnalysis();
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
		options.registerOption(OPTION_NAME_PYTHON_EXEC, pythonExec,
				null, OPTION_DESCRIPTION_PYTHON_EXEC);	
	}
	
    @Override
    public void optionsChanged(Options options, Program program) {
            pythonExec = options.getString(OPTION_NAME_PYTHON_EXEC, pythonExec);
    }

    private boolean checkError(DeepCutPython deepcut, MessageLog log)
    {
		String error = deepcut.readProcessError();			
		if (!error.isEmpty()) {
			log.appendMsg(error);
			return true;			
		}
  
		return false;
    }
    
	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		
		DeepCutPython deepcut = new DeepCutPython(pythonExec);
		FunctionCallGraph fcg = new FunctionCallGraph(program, monitor);
		
		try {
			deepcut.startProcess();
		
			if (checkError(deepcut, log)) {
				return false;
			}
			
			deepcut.writeProcess(fcg.toJson() + "\n");
			deepcut.waitFor();

			if (checkError(deepcut, log)) {
				return false;
			}			
			
			String cuts_json = deepcut.readProcessOutput();

			
			Cut[] cuts = new GsonBuilder().create().fromJson(cuts_json, Cut[].class);

			int i = 0;
			for (FunctionInfo fi : fcg.getFunctionInfos()) {
				AddressFactory af = program.getAddressFactory();
				Address cutAddress = af.getAddress(cuts[i].address);
				
				if (fi.getAddress().compareTo(cutAddress) == -1) {
					addNamespace(program, "object" + i, fi.getFunction());
				} else {
					i++;
					addNamespace(program, "object" + i, fi.getFunction());
				}				
			}		
		} catch (Exception e) {
			log.appendException(e);
			return false;
		}
		
		return true;
	}
	


	public void addNamespace(Program program, String name, Function function)
			throws DuplicateNameException, InvalidInputException, CircularDependencyException {
        SymbolTable symbolTable = program.getSymbolTable();
        Namespace namespace = null;
		
        namespace = symbolTable.getNamespace(name, null);
        if(namespace == null) {
        	namespace = symbolTable.createNameSpace(null, name,
                                                        SourceType.USER_DEFINED);
        }

        function.setParentNamespace(namespace);
    }

}
