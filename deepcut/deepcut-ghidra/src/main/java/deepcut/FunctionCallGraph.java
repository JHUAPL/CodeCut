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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.annotations.*;

import ghidra.util.task.TaskMonitor;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.address.Address;


class FunctionCallGraph {
	private TaskMonitor monitor;
	private Program program;
    private FlatProgramAPI api;

    // map from ghidra functions to my function class.
    public Map<Function, FunctionInfo> functionMap;
	
    // list of functions, sorted by address
	@Expose(serialize = true)
	@SerializedName(value="functions")
    public List<FunctionInfo> functionList;

    // Adjacency list of edges
	@Expose(serialize = true)
	@SerializedName(value="edges")
    public List<EdgeInfo> edgeList;


    public FunctionCallGraph(Program program, TaskMonitor monitor) {
        this.program = program;
        this.monitor = monitor;
        api = new FlatProgramAPI(program);

        functionList = new ArrayList<FunctionInfo>();
        functionMap = new HashMap<Function, FunctionInfo>();
        edgeList = new ArrayList<EdgeInfo>();

        createListOfFunctions();
        createListOfEdges();
    }

    private void createListOfFunctions() {
        // Returns an iterator over all non-external functions in address (entry point) order.
        FunctionIterator iter = program.getFunctionManager().getFunctions(true);

        int index = 0;
        while (iter.hasNext()) {
            Function function = iter.next();

            FunctionInfo func_info = new FunctionInfo(function);
            func_info.setAddressIndex(index++);

            functionList.add(func_info);
            functionMap.put(function, func_info);
        }
    }

    private void createListOfEdges() {
        for (FunctionInfo func_info : functionList) {
            Function function = func_info.getFunction();

            Map<Function, Integer> hm = getCountCallingFunctions(function);

            for (Map.Entry<Function, Integer> val : hm.entrySet()) {
                Function src = val.getKey();
                int multiplicity = val.getValue();

                // no idea why, but sometimes `src` is null.
                if (src == null) continue;

                // set the `is_recursive` flag if the function calls itself
                if(function.equals(src)) {
                    func_info.setIsRecursive(true);
                    continue;
                }

                // create the edge and add it to each list.
                FunctionInfo src_func_info = functionMap.get(src);
                EdgeInfo edge_info = new EdgeInfo(src_func_info, func_info, multiplicity);
                edgeList.add(edge_info);
                func_info.addIncomingEdge(edge_info);
                src_func_info.addOutgoingEdge(edge_info);
            }
            // remove the recursive call, if applicable.
            // Note: does nothing if `function` not in `hm`
            hm.remove(function);
        }
    }

    /*
    return a hashmap of the number of times each function calls this function.
     */
    private Map<Function, Integer> getCountCallingFunctions(Function function) {

        // hashmap to store the frequency of element
        Map<Function, Integer> hm = new HashMap<Function, Integer>();

        /*
         first populate the hashmap with all the calling functions.
         this is needed b/c `getCallingFunctions` returns some functions which
         `getReferencesTo` doesn't pick up on.

         I think this is b/c `getCallingFunctions` just tracks any xref.
         */
        Set<Function> calling_funcs = function.getCallingFunctions(monitor);

        for (Function f : calling_funcs) {
            hm.put(f, 0);
        }

        // then populate the counts
        Address entryPoint = function.getEntryPoint();
        Reference[] references = api.getReferencesTo(entryPoint);

        ArrayList<Function> func_list = new ArrayList<Function>();

        for(Reference r : references) {
            RefType rt = r.getReferenceType();
            boolean xref_is_call = rt.isCall() || rt.isJump();
            if (xref_is_call) {
                Address toAddress = r.getFromAddress();
                Function func = api.getFunctionContaining(toAddress);
                func_list.add(func);
            }
        }

        for (Function f : func_list) {
            Integer j = hm.get(f);
            hm.put(f, (j == null) ? 1 : j + 1);
        }

        return hm;
    }

	public List<FunctionInfo> getFunctionInfos() {
		return functionList;
	}
	
	public String toJson() {
		Gson gson = new GsonBuilder()
			.excludeFieldsWithoutExposeAnnotation()
			.registerTypeAdapter(FunctionInfo.class, new FunctionInfoSerializer())
			.registerTypeAdapter(EdgeInfo.class, new EdgeInfoSerializer())
			.create();

		return gson.toJson(this);
	}
	
    @Override
    public String toString() {
        StringBuilder str = new StringBuilder();
        str.append("Function List:\n");

        for(FunctionInfo fi : functionList) {
            str.append("{\"name\": \"" + fi.getName() +
					   "\", \"addr\": \"0x" + fi.getAddress() +
					   "\", \"idx\": " + fi.getAddressIndex() +
					   ", \"num_incoming_edges\": " + fi.getIncomingEdges().size() +
					   ", \"num_outgoing_edges\": " + fi.getOutgoingEdges().size() + "}\n");
        }

        str.append("\nEdge List:\n");
        for(EdgeInfo ei : edgeList) {
            str.append("{\"src_idx\": " + ei.getSrc().getAddressIndex() +
					   ", \"dst_idx\": " + ei.getDst().getAddressIndex() +
					   ", \"multiplicity\": " + ei.getMultiplicity() +
					   ", \"addr_dst\": " + ei.getAddressDistance() +
					   ", \"idx_dst\": " + ei.getIndexDistance() + "}\n");
        }

		return str.toString();
    }
}
