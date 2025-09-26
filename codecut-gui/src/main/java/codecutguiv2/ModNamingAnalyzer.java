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

import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.script.GhidraScriptLoadException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.util.DefinedStringIterator;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.Swing;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.datastruct.ListAccumulator;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

public class ModNamingAnalyzer {

    // Assumes these exist in your class, as in your original snippet:
    private Map<Namespace, List<String>> stringMap = new HashMap<>();
    private Map<Namespace, String> suggestedModuleNames = new HashMap<>();
    Program currentProgram;

    private static final String SEPARATOR = "tzvlw"; // separator used by modnaming.py
    
    ModNamingAnalyzer(Program currentProgram) {
    	this.currentProgram = currentProgram;
    	getModuleStrings();
    }
    
    public void getModuleStrings() {
		try {	
			SymbolTable symbolTable = currentProgram.getSymbolTable();
			ReferenceManager refManager = currentProgram.getReferenceManager();
			
			TaskMonitor monitor = new TaskMonitorAdapter();
			monitor.setCancelEnabled(true);
			Listing listing = currentProgram.getListing();
			monitor.initialize(listing.getNumDefinedData());
			
			Accumulator<ProgramLocation> accumulator = new ListAccumulator<>();

			Swing.allowSwingToProcessEvents();
			for (Data stringInstance : DefinedStringIterator.forProgram(currentProgram)) {
				Address strAddr = stringInstance.getAddress();
				ReferenceIterator refIterator = refManager.getReferencesTo(strAddr);
				while (refIterator.hasNext()) {
					Reference ref = refIterator.next();
					Namespace refNamespace = symbolTable.getNamespace(ref.getFromAddress());
					Namespace parentNs = refNamespace.getParentNamespace();
					String str = StringDataInstance.getStringDataInstance(stringInstance).getStringValue();
					
					// parent namespace is correct one to use BUT MAY BE NULL IF GLOBAL WAS ORIGINAL
					Namespace module;
					if (parentNs != null) {
						module = parentNs;
					}
					else {
						module = refNamespace;
					}
					
					List<String> list = stringMap.get(module);
					if (list != null) {
						list.add(str);
						stringMap.put(module, list);
					}
					else {
						List<String> newList = new ArrayList<String>();
						newList.add(str);
						stringMap.put(module, newList);
					}
				}
				
				ProgramLocation pl = new ProgramLocation(currentProgram, stringInstance.getMinAddress(), 
						stringInstance.getComponentPath(), null, 0, 0, 0);
				
				accumulator.add(pl);
				//monitor.checkCanceled();
				monitor.incrementProgress(1);
			}
			
		} catch (Exception e) {
			Msg.error(this, "Error when getting strings for each module: " + e);
			e.printStackTrace();
		}
	}
    
    private String packStrings(List<String> strList) {
    	String allStrings = String.join(" " + SEPARATOR + " ", strList);
		
		allStrings = allStrings.replaceAll("%[0-9A-Za-z]+"," ");
		allStrings = allStrings.replaceAll("-","_");
		allStrings = allStrings.replaceAll("_"," ");
		allStrings = allStrings.replaceAll("[/\\\\]"," ");
		allStrings = allStrings.replaceAll("[^A-Za-z0-9_.]"," ");
		allStrings = allStrings.concat("\r\n\0");
		
		return allStrings;
    }
    
    
    public void guessModuleNames() {
		Task guessNamesTask = new Task("Guess Module Names", true, true, true) {
			@Override 
			public void run(TaskMonitor monitor) {
				monitor.setMessage("Gathering string information...");
				long startCount = stringMap.size();
				long numRemaining = stringMap.size();
				monitor.initialize(startCount);
				
				// Force the updating state so the CodeCut GUI does not attempt to refresh
				// until after all updates are complete (makes things MUCH faster).
				CodecutUtils.setUpdating(true);
				
				try {
					for (Map.Entry<Namespace, List<String>> entry : stringMap.entrySet()) {		
						
						if (!monitor.isCancelled()) {
							Namespace ns = entry.getKey();
							
							if (!ns.getName().equals("Global")) {
								List<String> strList = entry.getValue();
								monitor.setMessage("Guessing module name for " + ns.getName());
								
								String allStrings = packStrings(strList);
								
								AddressSetView set = ns.getBody();
								if (set == null || set.isEmpty()) {
								    set = new AddressSet(currentProgram.getMinAddress(), currentProgram.getMaxAddress());
								}

								
								String suggestedName = ModNamingLauncher.execute(currentProgram, set, allStrings, monitor);
								
								//if name is "unknown" (e.g. modnaming found no repeated strings) don't bother renaming 
								if (suggestedName.equals("unknown")) {
									Msg.info(this, "No name guess found for module " + ns.getName() + ", leaving unchanged");
									continue;
								}

								suggestedModuleNames.put(ns, suggestedName);
								
								// Update namespace (module) to use new name
								// suggestedModuleNames is created in case this is later 
								// extended to have a GUI window for the user to accept/modify
								// names before updating, in which case this update should
								// happen elsewhere.
								monitor.setMessage("Updating module name of " + ns.getName() + "...");
								String newName = suggestedName;
								int num = 1;
								while (!CodecutUtils.getMatchingNamespaces(newName, Arrays.asList(currentProgram.getGlobalNamespace()), currentProgram).isEmpty()) {
									newName = suggestedName.concat(Integer.toString(num));
									num++;
								}
								Namespace newNs = null;
								
								int transactionId = currentProgram.startTransaction("CreateNamespace");
								boolean success = false;
								try {
								    newNs = currentProgram.getSymbolTable()
								            .createNameSpace(ns.getParentNamespace(), newName, SourceType.USER_DEFINED);
								    success = true;
								} catch (DuplicateNameException ex) {
								    Msg.error(this, "Failed to create namespace for suggested name " + suggestedName, ex);
								} finally {
								    currentProgram.endTransaction(transactionId, success);
								}
								
								try {
									CodecutUtils.renameNamespace(currentProgram, ns, newNs);
									Msg.info(this, "Namespace " + ns.getName() + " renamed to " + newNs.getName());
								} catch (Exception ex) {
									Msg.info(this, "Exception when renaming namespace " + ns.getName() + ": " + ex.getMessage());
									
								}
							}
							numRemaining--;
							monitor.setProgress(startCount - numRemaining);
						}
						else { // Task cancelled
							suggestedModuleNames.clear();
							suggestedModuleNames = null;
						}
					}
							
				} catch (Exception e) {
					Msg.error(this, "Module name guessing failed: " + e);
					e.printStackTrace();
				}
				CodecutUtils.setUpdating(false);
				
			}
		};
		
		new TaskLauncher(guessNamesTask, null, 250);
	}
    
    
}




class ModNamingLauncher extends PyGhidraFileLauncher {

    @Override protected String getScriptName() { return "ModNamingRun.py"; }
    @Override protected String getInfilePrefix() { return "modnaming_in"; }
    @Override protected String getOutfilePrefix() { return "modnaming_out"; }
    @Override protected String getInfileSuffix() { return ".txt"; }
    @Override protected String getOutfileSuffix() { return ".txt"; }

    // No extra args needed
    @Override protected String[] getExtraArgs(ghidra.framework.plugintool.PluginTool tool) { return new String[0]; }

    // Convenience static method to preserve your old call-site signature
    public static String execute(Program program,
                                     AddressSetView set,
                                     String inputPayload,
                                     TaskMonitor monitor)
            throws IllegalAccessException, FileNotFoundException, GhidraScriptLoadException {
        return new ModNamingLauncher().runFileMode(program, set, inputPayload, monitor);
    }

    @Override protected String getLaunchFailDialogTitle() { return "Module Naming Failed to Launch"; }
    @Override protected String getLaunchFailDialogBodyPrefix() {
        return "Module Naming requires the PyGhidra extension.\n\nDetails: ";
    }
}


