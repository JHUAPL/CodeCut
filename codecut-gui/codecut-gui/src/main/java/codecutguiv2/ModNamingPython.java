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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader; 
import java.io.OutputStream;
import java.util.stream.Collectors;
import docking.widgets.dialogs.MultiLineMessageDialog;
import ghidra.framework.Application;

public class ModNamingPython {
	public Runtime runtime;
	public String pythonExec;
	
	public Process process;
	public OutputStream stdin;
	public InputStream stdout;
	public InputStream stderr;
	
	public ModNamingPython(String pythonExec) {
		this.pythonExec = pythonExec;
		this.runtime = Runtime.getRuntime();
	}
	
	public int startProcess() throws IOException {
		String pythonFile = Application.getModuleDataFile("modnaming.py").toString();
		
		String[] exec = {pythonExec, pythonFile};
		
		try {
			process = runtime.exec(exec);
		}
		catch (IOException e) {
			// show message about invalid python executable path
			MultiLineMessageDialog.showMessageDialog(null, "Invalid Python Path", 
					"Python Error! Please check path under " +
					"\n Edit -> Tool Options -> Python Executable.",
					e.getMessage(), MultiLineMessageDialog.WARNING_MESSAGE);
			return -1;
			
		}

		// Yes this is confusing. stdin is a Java OutputStream, stdin is an InputStream
		stdin = process.getOutputStream();
		stdout = process.getInputStream();
		stderr = process.getErrorStream();	
		return 0;
	}
	
	public void waitFor() throws InterruptedException {
		process.waitFor();
	}
	
	public void writeProcess(String data) throws IOException {
		writeProcess(data.getBytes());
	}
	
	public void writeProcess(byte[] data) throws IOException {
		stdin.write(data);
		stdin.flush();
	}
	
	public String readProcessOutput() {
		return readProcess(stdout);
	}
	
	public String readProcessError() {
		return readProcess(stderr);
	}
	
	public String readProcess(InputStream stream) {
		String result = "";
		
		try {
			if (stream != null && stream.available() > 0) {
				result = new BufferedReader(new InputStreamReader(stream))
								.lines().collect(Collectors.joining("\n"));
			}
		} catch (IOException e) {
			return result;
		}
		
		return result;
	}
}
