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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import ghidra.app.util.SymbolPath;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.program.model.address.GlobalNamespace;
import ghidra.program.model.listing.CircularDependencyException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Library;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/**
 * A class to hold utility methods for working with namespaces.
 * <p>
 * <a id="examples"></a>
 * Example string format:
 * <ul>
 *     <li>global{@link Namespace#DELIMITER ::}child1{@link Namespace#DELIMITER ::}child2
 *     <li>child1
 * </ul>
 * <a id="assumptions"></a>
 * <b>Assumptions for creating namespaces from a path string: </b>
 * <ul>
 *     <li>All elements of a namespace path should be namespace symbols and not other
 *         symbol types.         
 *     <li>Absolute paths can optionally start with the global namespace.
 *     <li>You can provide a relative path that will start at the given
 *         parent namespace (or global if there is no parent provided).
 *     <li>You can provide a path that has as its first entry the name of the
 *         given parent.  In this case, the first entry will not be created,
 *         but rather the provided parent will be used.
 *     <li>If you provide a path and a parent, but the first element of the
 *         path is the global namespace, then the global namespace will be
 *         used as the parent namespace and not the one that was provided.
 *     <li>You cannot embed the global namespace in a path, but it can be at
 *         the root.
 * </ul>
 *
 *
 */
public class CodecutUtils {
	
	private static boolean updatingNamespace;
	private static boolean setUpdating;
	private static boolean transferring; 
	private static boolean setTransferring; 
	private static NewSymbolFilter filter; 

	private CodecutUtils() {
		// singleton utils class--no public construction
		updatingNamespace = false;
		setUpdating = false;
		transferring = false; 
		setTransferring = false; 
		filter = new NewSymbolFilter(); 
	}

	public static void setFilter(NewSymbolFilter filt) {
		filter = new NewSymbolFilter(filt);
	}
	
	public static NewSymbolFilter getFilter() {
		return CodecutUtils.filter; 
	}
	/**
	 * Get the normal namespace path excluding any library name.  Global namespace will be
	 * returned as empty string, while other namespace paths will be returned with trailing ::
	 * suffix.
	 * @param namespace namespace
	 * @return namespace path excluding any library name
	 */
	public static String getNamespacePathWithoutLibrary(Namespace namespace) {
		String str = new String();
		while (namespace != null && !(namespace instanceof GlobalNamespace) &&
			!(namespace instanceof Library)) {
			str = namespace.getName() + Namespace.DELIMITER + str;
			namespace = namespace.getParentNamespace();
		}
		return str;
	}

	/**
	 * Get namespace qualified symbol name
	 * @param namespace namespace object
	 * @param symbolName name of symbol
	 * @param excludeLibraryName if true any library name will be excluded from path returned,
	 * otherwise it will be included
	 * @return namespace qualified symbol name
	 */
	public static String getNamespaceQualifiedName(Namespace namespace, String symbolName,
			boolean excludeLibraryName) {
		String str = "";
		if (excludeLibraryName && namespace.isExternal()) {
			str = getNamespacePathWithoutLibrary(namespace);
		}
		else if (namespace != null && !(namespace instanceof GlobalNamespace)) {
			str = namespace.getName(true) + Namespace.DELIMITER;
		}
		str += symbolName;
		return str;
	}

	/**
	 * Provide a standard method for splitting a symbol path into its
	 * various namespace and symbol name elements.  While the current implementation
	 * uses a very simplistic approach, this may be improved upon in the future
	 * to handle various grouping concepts.
	 * @param path symbol namespace path (path will be trimmed before parse)
	 * @return order list of namespace names
	 * @deprecated use SymbolPath instead
	 */
	@Deprecated
	public static List<String> splitNamespacePath(String path) {
		return Arrays.asList(path.trim().split(Namespace.DELIMITER));
	}

	/**
	 * Get the library associated with the specified namespace
	 * @param namespace namespace
	 * @return associated library or null if not associated with a library
	 */
	public static Library getLibrary(Namespace namespace) {
		Namespace ns = namespace;
		while (ns.isExternal()) {
			if (ns instanceof Library) {
				return (Library) ns;
			}
			ns = ns.getParentNamespace();
		}
		return null;
	}

	public static List<Namespace> getAllNamespaces(Program program) {
		List<Namespace> namespaceList = new ArrayList<>();
		SymbolIterator iter = program.getSymbolTable().getDefinedSymbols();
		while (iter.hasNext()) {
			Symbol symbol = iter.next();
			SymbolType type = symbol.getSymbolType();
			if (type == SymbolType.FUNCTION) {
				Namespace ns = ((Function)symbol.getObject()).getParentNamespace();
				if (!namespaceList.contains(ns)) {
					namespaceList.add(ns);
				}
			}
		}
		return namespaceList;
	}

	/**
	 * Returns a list of all namespaces with the given name in the parent namespace
	 * 
	 * @param program the program to search
	 * @param parent the parent namespace from which to find all namespaces with the given name;
	 *        if null, the global namespace will be used
	 * @param namespaceName the name of the namespaces to retrieve
	 * @return a list of all namespaces that match the given name in the given parent namespace.
	 */
	public static List<Namespace> getNamespacesByName(Program program, Namespace parent,
			String namespaceName) {
		validate(program, parent);
		List<Namespace> namespaceList = new ArrayList<>();
		List<Symbol> symbols = program.getSymbolTable().getSymbols(namespaceName, parent);
		for (Symbol symbol : symbols) {
			if (symbol.getSymbolType().isNamespace()) {
				namespaceList.add((Namespace) symbol.getObject());
			}
		}
		return namespaceList;
	}

	/**
	 * Returns a list of namespaces that match the given path.  The path can be
	 * relative to the given root namespace or absolute if the path begins with
	 * the global namespace name.
	 *
	 * <P>Note: this path must only contain Namespace names and no other symbol types.
	 * 
	 * @param program the program to search
	 * @param parent the namespace to use as the root for relative paths. If null, the
	 * 		  global namespace will be used
	 * @param pathString the path to the desired namespace
	 * @return a list of namespaces that match the given path
	 */
	public static List<Namespace> getNamespaceByPath(Program program, Namespace parent,
			String pathString) {

		validate(program, parent);

		parent = adjustForNullRootNamespace(parent, pathString, program);

		SymbolPath path = new SymbolPath(parent.getSymbol());
		if (pathString != null) {
			path = path.append(new SymbolPath(pathString));
		}

		List<String> namespaceNames = path.asList();
		List<Namespace> namespaces = doGetNamespaces(namespaceNames, parent, program);
		return namespaces;
	}

	private static List<Namespace> doGetNamespaces(List<String> namespaceNames,
			Namespace root, Program program) {

		if (root == null) {
			root = program.getGlobalNamespace();
		}

		List<Namespace> parents = Arrays.asList(root);
		for (String name : namespaceNames) {
			List<Namespace> matches = getMatchingNamespaces(name, parents, program);
			parents = matches;
		}
		return parents;
	}

	/**
	 * Returns a list all namespaces that have the given name in any of the given namespaces
	 *
	 * @param childName the name of the namespaces to retrieve
	 * @param parents a list of all namespaces to search for child namespaces with the given name
	 * @param program the program to search
	 * @return a list all namespaces that have the given name in any of the given namespaces
	 */
	public static List<Namespace> getMatchingNamespaces(String childName, List<Namespace> parents,
			Program program) {
		validate(program, parents);
		List<Namespace> list = new ArrayList<>();
		for (Namespace parent : parents) {
			list.addAll(getNamespacesByName(program, parent, childName));
		}

		return list;
	}

	/**
	 * Returns a list all symbols that have the given name in any of the given
	 * parent namespaces.
	 *
	 * @param parents a list of all namespaces to search for symbols with the given name.
	 * @param symbolName the name of the symbols to retrieve.
	 * @param program the program to search.
	 * @return a list all symbols that have the given name in any of the given namespaces.
	 */
	private static List<Symbol> searchForAllSymbolsInAnyOfTheseNamespaces(List<Namespace> parents,
			String symbolName, Program program) {

		List<Symbol> list = new ArrayList<>();
		for (Namespace parent : parents) {
			list.addAll(program.getSymbolTable().getSymbols(symbolName, parent));
		}

		return list;

	}

	/**
	 * Returns a list of all symbols that match the given path. The path consists of a series
	 * of namespaces names separated by "::" followed by a label or function name.
	 *
	 * @param symbolPath the names of namespaces and symbol separated by "::".
	 * @param program the program to search
	 * @return the list of symbols that match the given
	 */
	public static List<Symbol> getSymbols(String symbolPath, Program program) {

		List<String> namespaceNames = new SymbolPath(symbolPath).asList();
		if (namespaceNames.isEmpty()) {
			return Collections.emptyList();
		}

		String symbolName = namespaceNames.remove(namespaceNames.size() - 1);
		List<Namespace> parents =
			doGetNamespaces(namespaceNames, program.getGlobalNamespace(), program);
		return searchForAllSymbolsInAnyOfTheseNamespaces(parents, symbolName, program);
	}

	/**
	 * Returns a list of Symbol that match the given symbolPath.
	 *
	 * @param symbolPath the symbol path that specifies a series of namespace and symbol names.
	 * @param program the program to search for symbols with the given path.
	 * @return  a list of Symbol that match the given symbolPath.
	 */
	public static List<Symbol> getSymbols(SymbolPath symbolPath, Program program) {
		SymbolPath parentPath = symbolPath.getParent();
		if (parentPath == null) {
			return program.getSymbolTable().getGlobalSymbols(symbolPath.getName());
		}
		List<Namespace> parents = doGetNamespaces(parentPath.asList(), null, program);
		return searchForAllSymbolsInAnyOfTheseNamespaces(parents, symbolPath.getName(), program);
	}

	/**
	 * Returns the first namespace with the given name and that is NOT a function that
	 * is within the parent namespace. (ie. the first namespace that is not tied to a program
	 * address)
	 *
	 * @param parent the parent namespace to search
	 * @param namespaceName the name of the namespace to find
	 * @param program the program to search.
	 * @return the first namespace that matches, or null if no match.
	 */
	public static Namespace getFirstNonFunctionNamespace(Namespace parent, String namespaceName,
			Program program) {
		validate(program, parent);
		List<Symbol> symbols = program.getSymbolTable().getSymbols(namespaceName, parent);
		for (Symbol symbol : symbols) {
			if (symbol.getSymbolType().isNamespace() &&
				symbol.getSymbolType() != SymbolType.FUNCTION) {
				return (Namespace) symbol.getObject();
			}
		}
		return null;
	}

	/**
	 * Takes a namespace path string and creates a namespace hierarchy to
	 * match that string.  This method ignores function namespaces so the path
	 * should not contain any function names.  If you want traverse down through
	 * functions, then use the version that also takes an address that is used to distinguish
	 * between multiple functions with the same name.
	 * <P>
	 * The root namespace can be a function.
	 *
	 *
	 * @param  namespacePath The namespace name or path string to be parsed.
	 *         This value should not include a trailing symbol name, only namespace names.
	 * @param  rootNamespace The parent namespace under which the desired
	 *         namespace or path resides.  If this value is null, then the
	 *         global namespace will be used. This namespace can be a function name;
	 * @param  program The current program in which the desired namespace
	 *         resides.
	 * @param  source the source type of the namespace
	 * @return The namespace that matches the given path.  This can be either an existing
	 *         namespace or a newly created one.
	 * @throws InvalidInputException If a given namespace name is in an
	 *         invalid format and this method attempts to create that
	 *         namespace, or if the namespace string contains the global
	 *         namespace name in a position other than the root.
	 * @see    <a href="#assumptions">assumptions</a>
	 */
	public static Namespace createNamespaceHierarchy(String namespacePath, Namespace rootNamespace,
			Program program, SourceType source) throws InvalidInputException {
		return createNamespaceHierarchy(namespacePath, rootNamespace, program, null, source);
	}

	/**
	 * Takes a namespace path string and creates a namespace hierarchy to
	 * match that string.  This method allows function namespaces in the path
	 * and uses the given address to resolve functions with duplicate names.  When
	 * resolving down the namespace path, a function that matches a name will only
	 * be used if the given address is contained in the body of that function.
	 * 
	 * <p>The root namespace can be a function.
	 * 
	 * <p>If an address is passed, then the path can contain a function name provided the 
	 * address is in the body of the function; otherwise the names must all be namespaces other 
	 * than functions.
	 *
	 * @param  namespacePath The namespace name or path string to be parsed
	 *         This value should not include a trailing symbol name, only namespace names
	 * @param  rootNamespace The parent namespace under which the desired
	 *         namespace or path resides.  If this value is null, then the
	 *         global namespace will be used.
	 * @param  program The current program in which the desired namespace
	 *         resides
	 * @param  address the address used to resolve possible functions with duplicate names; may
	 *         be null
	 * @param  source the source of the namespace
	 * @return The namespace that matches the given path.  This can be either an existing
	 *         namespace or a newly created one.
	 * @throws InvalidInputException If a given namespace name is in an
	 *         invalid format and this method attempts to create that
	 *         namespace, or if the namespace string contains the global
	 *         namespace name in a position other than the root.
	 * @see    <a href="#assumptions">assumptions</a>
	 */
	public static Namespace createNamespaceHierarchy(String namespacePath, Namespace rootNamespace,
			Program program, Address address, SourceType source) throws InvalidInputException {
		validate(program, rootNamespace);
		rootNamespace = adjustForNullRootNamespace(rootNamespace, namespacePath, program);
		if (namespacePath == null) {
			return rootNamespace;
		}

		SymbolPath path = new SymbolPath(namespacePath);
		List<String> namespacesList = path.asList();

		SymbolTable symbolTable = program.getSymbolTable();
		Namespace namespace = rootNamespace;
		for (String namespaceName : namespacesList) {
			Namespace ns = getNamespace(program, namespace, namespaceName, address);
			if (ns == null) {
				try {
					ns = symbolTable.createNameSpace(namespace, namespaceName, source);
				}
				catch (DuplicateNameException e) {
					throw new AssertException(
						"Duplicate name exception should not be possible here since we checked first!");
				}
			}
			namespace = ns;
		}

		return namespace;
	}

	/**
	 * Returns the existing Function at the given address if its {@link SymbolPath} matches the
	 * given path  
	 *
	 * @param program the program
	 * @param symbolPath the path of namespace
	 * @param address the address 
	 * @return the namespace represented by the given path, or null if no such namespace exists
	 */
	public static Namespace getFunctionNamespaceAt(Program program, SymbolPath symbolPath,
			Address address) {

		if (symbolPath == null || address == null) {
			return null;
		}

		Symbol[] symbols = program.getSymbolTable().getSymbols(address);
		for (Symbol symbol : symbols) {
			if (symbol.getSymbolType() == SymbolType.FUNCTION &&
				symbolPath.matchesPathOf(symbol)) {
				return (Function) symbol.getObject();
			}
		}
		return null;
	}

	/**
	 * Returns the existing Function containing the given address if its 
	 * {@link SymbolPath} matches the given path  
	 *
	 * @param program the program
	 * @param symbolPath the path of namespace
	 * @param address the address 
	 * @return the namespace represented by the given path, or null if no such namespace exists
	 */
	public static Namespace getFunctionNamespaceContaining(Program program, SymbolPath symbolPath,
			Address address) {

		if (symbolPath == null || address == null) {
			return null;
		}

		FunctionManager fm = program.getFunctionManager();
		Function f = fm.getFunctionContaining(address);
		if (f != null) {
			if (symbolPath.matchesPathOf(f.getSymbol())) {
				return f;
			}
		}
		return null;
	}

	/**
	 * Finds the namespace for the given symbol path <b>that is not a function</b>
	 *
	 * @param program the program from which to get the namespace
	 * @param symbolPath the path of namespace names including the name of the desired namespace
	 * @return the namespace represented by the given path, or null if no such namespace exists or
	 *         the namespace is a function
	 */
	public static Namespace getNonFunctionNamespace(Program program, SymbolPath symbolPath) {

		if (symbolPath == null) {
			return program.getGlobalNamespace();
		}

		List<Symbol> symbols = getSymbols(symbolPath, program);
		for (Symbol symbol : symbols) {
			if (symbol.getSymbolType() != SymbolType.FUNCTION &&
				symbol.getSymbolType().isNamespace()) {
				return (Namespace) symbol.getObject();
			}
		}
		return null;
	}

	private static Namespace getNamespace(Program program, Namespace parent, String name,
			Address address) {

		if (parent == null) {
			return null;
		}

		List<Symbol> symbols = program.getSymbolTable().getSymbols(name, parent);

		// first see if there are any functions and if they contain the given address
		if (address != null) {
			for (Symbol symbol : symbols) {
				if (symbol.getSymbolType() == SymbolType.FUNCTION) {
					Function function = (Function) symbol.getObject();
					if (function.getBody().contains(address)) {
						return function;
					}
				}
			}
		}
		// otherwise just see if there is a non-function namespace
		for (Symbol symbol : symbols) {
			SymbolType type = symbol.getSymbolType();
			if (type != SymbolType.FUNCTION && type.isNamespace()) {
				return (Namespace) symbol.getObject();
			}
		}

		return null;
	}

	private static Namespace adjustForNullRootNamespace(Namespace parentNamespace,
			String namespacePath, Program program) {
		Namespace globalNamespace = program.getGlobalNamespace();
		if (namespacePath != null && namespacePath.startsWith(globalNamespace.getName())) {
			return globalNamespace;
		}

		if (parentNamespace != null) {
			return parentNamespace;
		}

		return globalNamespace;
	}

	private static void validate(Program program, Namespace namespace) {
		if (namespace != null && !namespace.isGlobal()) {
			if (program != namespace.getSymbol().getProgram()) {
				throw new IllegalArgumentException(
					"Given namespace does not belong to the given program");
			}
		}
	}

	private static void validate(Program program, List<Namespace> parents) {
		for (Namespace namespace : parents) {
			validate(program, namespace);
		}
	}

	/**
	 * Convert a namespace to a class by copying all namespace children into a newly created class
	 * and then removing the old namespace
	 * 
	 * @param namespace namespace to be converted
	 * @return new class namespace
	 * @throws InvalidInputException if namespace was contained within a function and can not be
	 * 			converted to a class
	 */
	public static GhidraClass convertNamespaceToClass(Namespace namespace)
			throws InvalidInputException {

		Symbol namespaceSymbol = namespace.getSymbol();
		String name = namespaceSymbol.getName();
		SourceType originalSource = namespaceSymbol.getSource();

		SymbolTable symbolTable = namespaceSymbol.getProgram().getSymbolTable();

		// Temporarily rename old namespace (it will be removed at the end)
		int count = 1;
		while (true) {
			String n = name + "_" + count++;
			try {
				namespaceSymbol.setName(n, SourceType.ANALYSIS);
				break;
			}
			catch (DuplicateNameException e) {
				// continue
			}
			catch (InvalidInputException e) {
				throw new AssertException(e);
			}
		}

		// create new class namespace
		GhidraClass classNamespace = null;
		try {
			classNamespace =
				symbolTable.createClass(namespace.getParentNamespace(), name, originalSource);
		}
		catch (DuplicateNameException e) {
			throw new AssertException(e);
		}
		catch (InvalidInputException e) {
			// The only cause of this exception can be assumed but we need to
			// avoid showing the user a temporary name
			throw new InvalidInputException(
				"Namespace contained within Function may not be converted to a class: " + name);
		}

		// move everything from old namespace into new class namespace
		try {
			for (Symbol s : symbolTable.getSymbols(namespace)) {
				s.setNamespace(classNamespace);
			}
			namespaceSymbol.delete();
		}
		catch (DuplicateNameException | InvalidInputException | CircularDependencyException e) {
			throw new AssertException(e);
		}
		return classNamespace;
	}
	
	public static boolean isFirstSymbolInNamespace(Program p, Symbol s) {
		SymbolIterator iterator =
				p.getSymbolTable().getSymbolIterator(s.getAddress().subtract(1), false);
		if (iterator.hasNext()) {
			Symbol prevSym = iterator.next();
			String prevSymNS = prevSym.getParentNamespace().toString();
			if (s.getParentNamespace().toString().equals(prevSymNS)) {
				return false;
			}
		}
		return true;
	}
	public static boolean isLastSymbolInNamespace(Program p, Symbol s) {
		SymbolIterator iterator =
				p.getSymbolTable().getPrimarySymbolIterator(s.getAddress().add(1), true);
		if (iterator.hasNext()) {
			Symbol nextSym = iterator.next();
			String nextSymNS = nextSym.getParentNamespace().toString();
			if (s.getParentNamespace().toString().equals(nextSymNS)) {
				return false;
			}
		}
		return true;
	}
	
	public static AddressRange getNamespaceRange(Program p, Symbol s) {
		//create backward & forward iterators
		SymbolIterator revIter;
		SymbolIterator fwdIter;
		Symbol prevUpSym = s, prevDnSym = s;
		Symbol upSym = s, dnSym = s;
		String upSymNS = s.getParentNamespace().toString();
		String dnSymNS = s.getParentNamespace().toString();
		String symNS = s.getParentNamespace().toString();
		
		try { 
			revIter = p.getSymbolTable().getSymbolIterator(s.getAddress().subtractNoWrap(1), false);
			//follow backward iterator until the NS doesn't match
			do {
				if (revIter.hasNext()) {
				  //ignore non-primary symbols
				  if (upSym.isPrimary()) {
				    prevUpSym = upSym;
				  }
				  upSym = revIter.next();
				  if (upSym.isPrimary()) {
					  upSymNS = upSym.getParentNamespace().toString();
				  }
				}
				
			} while (upSymNS.equals(symNS) && upSym.getAddress().hasSameAddressSpace(s.getAddress()) && revIter.hasNext());
		}
		catch (AddressOverflowException e) {
			//prevUpSym already set to s
		}
		
		try {
			fwdIter = p.getSymbolTable().getPrimarySymbolIterator(s.getAddress().addNoWrap(1), true);
			//follow forward iterator until NS doesn't match
			do {
			  if (fwdIter.hasNext()) {
				//don't have to check for primary here because we will always hit a primary symbol in a new namespace 
				prevDnSym = dnSym;
			    dnSym = fwdIter.next();
			    dnSymNS = dnSym.getParentNamespace().toString();
			  }
			
		    } while (dnSymNS.equals(symNS) && dnSym.getAddress().hasSameAddressSpace(s.getAddress()) && fwdIter.hasNext());
		}
		catch (AddressOverflowException e){
			//dnSym already set to s;
		}
		//Technically we should check here if dnSym is the last symbol in the program
		//then the end should be the end of the program.  But since we are applying
		//namespaces to symbols, this is ok.  This is something to watch out for if
		//we're going to export modules based on namespaces.
		
	
		Address end = dnSym.getAddress();
		//if we rolled into a new address space, pick the end of the symbol's address space
	    if (! dnSym.getAddress().hasSameAddressSpace(s.getAddress()) ) {
	    	end = s.getAddress().getAddressSpace().getMaxAddress();
	    }
	    //normal case - symbol within the current address space
	    else if (end.compareTo(s.getAddress()) != 0) {
			end = dnSym.getAddress().subtract(1); 
		}

		String msg = "address range:" + prevUpSym.getAddress().toString() + " " + end.toString();
		Msg.info(msg, msg);
		AddressRange a = new AddressRangeImpl(prevUpSym.getAddress(),end);
		
		return a;
	}
	
	
	public static AddressRange getNamespaceRange(Program p, Namespace ns) {
		if (ns.getName().equals("<EXTERNAL>")) {
			return null;
		}
		Address start = p.getMaxAddress();
		Address end = p.getMinAddress();
		SymbolIterator iter = p.getSymbolTable().getSymbols(ns);
		while (iter.hasNext()) {
			Symbol sym = iter.next();
			if (sym.getParentNamespace().equals(ns)) {
				Address symAddr = sym.getAddress();
				end = Address.max(symAddr, end);
				start = Address.min(symAddr, start);
			}
		}
		AddressRange addrRange = new AddressRangeImpl(start, end);
		return addrRange;
	}
	
	public static void renameNamespace(Program p, Namespace oldNamespace, Namespace newNamespace) throws DuplicateNameException, InvalidInputException, CircularDependencyException {
		if (oldNamespace.equals(newNamespace)) {
			return;
		}
		updatingNamespace = true;
		SymbolIterator iter = p.getSymbolTable().getSymbols(oldNamespace);
		Symbol currSym = null;
		int transactionID = p.startTransaction("nsRename");
		try {
			while (iter.hasNext()) {
				currSym = iter.next();
				currSym.setNamespace(newNamespace);
			}
			oldNamespace.getSymbol().delete();
		}
		catch (Exception e) {
			Msg.info(new Object(), "Could not set namespace for " + currSym.getName());
			Msg.info(new Object(), e.getMessage());
			p.endTransaction(transactionID, false);
		}
		p.endTransaction(transactionID, true);
		updatingNamespace = false;

	}
	
	//This is assuming that the namespace is contiguous and only appears once
	//The ideal situation would be either 
	//1) enforcing contiguousness (making new names _2, _3 etc.) when there are duplicates
	//2) actually making a "module" concept in the database which points to namespace but is separate
	public static void splitNamespace(Program p, Symbol s, Namespace newNamespace) {
		AddressRange a = getNamespaceRange(p,s);
		SymbolIterator iter = p.getSymbolTable().getSymbolIterator(s.getAddress(), true);
		Symbol currSym = s;
		updatingNamespace = true;
		
		int transactionID = p.startTransaction("nsSplit");
		try {
			do {
				currSym.setNamespace(newNamespace);
				currSym = iter.next();
				Msg.info(new Object(), "currSym.getAddress() =" + currSym.getAddress());
			} while (currSym.getAddress().compareTo(a.getMaxAddress()) <= 0);
		}
		catch (Exception e) {
			Msg.info(new Object(), "Trouble setting ns for symbol " + currSym.toString() + " to " + newNamespace.getName() );
			p.endTransaction(transactionID, false);
		}
		updatingNamespace = false;
		p.endTransaction(transactionID, true);
		
	}
	
	public static boolean nsUpdating() {
		return (updatingNamespace || setUpdating);
	}
	
	public static void setUpdating(boolean status) {
		setUpdating = status;
	}
	
	public static boolean transferring() {
		return (transferring || setTransferring);
	}
	
	public static void setTransferring(boolean status) {
		setTransferring = status; 
	}
}
