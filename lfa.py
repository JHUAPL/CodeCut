##############################################################################################
# Copyright 2018 The Johns Hopkins University Applied Physics Laboratory LLC
# All rights reserved.
# Permission is hereby granted, free of charge, to any person obtaining a copy of this 
# software and associated documentation files (the "Software"), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, 
# merge, publish, distribute, sublicense, and/or sell copies of the Software, and to 
# permit persons to whom the Software is furnished to do so.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, 
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR 
# PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE 
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, 
# TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE 
# OR OTHER DEALINGS IN THE SOFTWARE.
#
# HAVE A NICE DAY.

################################################################################
###  Object File Boundary Detection in IDA Pro with Local Function Affinity  ###
################################################################################

# LFA Metric
# Local Function Affinity (LFA) is a measurement of the direction a function
# is being "pulled" by the functions it calls and the functions that call it.
# By looking at an average of the log of the distance between these functions
# we get a measurement of whether the function is related to functions in the
# positive or negative direction.

# Edge Detection
# In a standard C/C++ development environment, the project is divided into
# multiple source files, which are compiled to object files, then linked into
# the final binary in order.  If external references are eliminated (LFA does
# this imperfectly by just eliminating calls whose distance is above a chosen
# threshold) we would expect to see LFA starting positive, switching to
# negative over the course of a source file, then switching back to positive
# at the beginning of the next file.  So object file boundaries 

# What is code anyway?
# Don't get too hung up on "object file boundaries" - for LFA (or any other
# attempt to solve the problem) to be perfect, the design and implementation
# of the code would have to be perfect.  What LFA is really finding is clusters
# of functionality, that should be more or less related to object files
# but it will often break up large object files into multiple clusters or
# detect 2 or 3 related object files as one file.

IDA_VERSION = 7

if (IDA_VERSION < 7):	
	import idc
	import struct
	import idautils
	import basicutils_6x as basicutils
else:
	import ida_idaapi
	import ida_idc
	import ida_funcs
	import ida_nalt
	import ida_segment
	import idautils
	import basicutils_7x as basicutils

import math
import nltk
import nltk.collocations

#Threshold above which a function call is considered "external"
#For published research - 0x1000 = 4K
MAX_CALL = 0x1000

#This is a list of the LFA scores for all functions
g_function_list = []

#This is a list of modules a.k.a. object files after the edge_detect()
#function is executed 
g_module_list = []


class func_info():
	def __init__(self,loc,score1,score2):
		self.loc = loc        #the effective address of the function
		self.score1=score1    #"Calls from" local function affinity score
		self.score2=score2    #"Calls to" local function affinity score 
		self.total_score=score1+score2
		self.edge=0           #Set by edge_detect() - if 1, this is the start of a new module
		
class bin_module():
	def __init__(self,start,end,score,name):
		self.start=start
		self.end=end
		self.score=score	#Currently unused
		self.name=name

#locate_module()
#Return the module information for a given function
#This assumes that the module list is in order, but not necessarily contiguous
def locate_module(f):
	global g_module_list
	found=0
	c=0
	#print "Finding %08x in module list length: %d" % (f,len(g_module_list))
	while ( (found != 1) and (c < len(g_module_list))):
		m = g_module_list[c]
		#print "\t%x - %x: %s" % (m.start,m.end,m.name)
		#this is the case where a function falls in the cracks between modules (because it wasn't cool enough to get a score)
		if (f < m.start):
			found = 1
			ret = None
		elif ((f >= m.start) and (f <= m.end)):
			found = 1
			ret = m
		c+=1
	return m	

#gen_mod_graph()
#Output a module-to-module call graph in GraphViz format
#For each module m_1
#  For each function <f> in the module
#    For each function that <f> calls
#      Lookup the module info for <f> m_2
#        If it's been assigned a module, add edge m_1 -> m_2 to the graph
def gen_mod_graph():
	global g_module_list
	c=0
	g=set()
	while (c < len(g_module_list)):
		m = g_module_list[c]
		f = m.start
		while (f <= m.end):
			for xref in basicutils.FuncXrefsFrom(f):
				target = locate_module(xref)
				if (target):
					g.add((m.name,target.name))
			f = basicutils.NextFunction(f)
		c+=1

	root_name = basicutils.GetInputFile()
	file = open(root_name + "_lfa_mod_graph.gv", "wb")
	
	file.write("digraph g {\n")
	
	for (node1,node2) in g:
		line = "%s -> %s\n" % (node1,node2)
		file.write(line)
		
	file.write("}\n")
	file.close()

#gen_rename_script()
#Output the module list with names as a Python script
#This script can then be run on the database if in the same directory as the basicutils libraries
#Look at basicutils.RenameRangeWithAddr to see the "canonical" name format - 
#  you can also tweak that function to use a different naming convention
def gen_rename_script():
	global g_module_list
	c=0

	root_name = basicutils.GetInputFile()
	file = open(root_name + "_lfa_labels.py", "wb")
	
	if (IDA_VERSION < 7):
		file.write("import basicutils_6x as basicutils\n");
	else:
		file.write("import basicutils_7x as basicutils\n");
	file.write("\ndef go():\n");
	
	while (c<len(g_module_list)):
		m=g_module_list[c]
		file.write("\tbasicutils.RenameRangeWithAddr(0x%x,0x%x,\"%s\")\n"%(m.start,m.end,m.name))
		c+=1
		
	file.write("\n")
	file.write("if __name__ == \"__main__\":\n")
	file.write("\treload(basicutils)\n")
	file.write("\tgo()\n")
	file.close()

#gen_map_file()
#Produce a .map file similar to that produced by the ld option -Map=foo.map
#Use map_read.py to test LFA's accuracy when a ground truth map file is available
def gen_map_file():
	global g_module_list
	c=0

	root_name = basicutils.GetInputFile()
	file = open(root_name + "_lfa_map.map", "wb")
	
	while (c<len(g_module_list)):
		m=g_module_list[c]
		mlen = idc.NextFunction(m.end) - m.start 
		mlen_str = "0x%x" % mlen
		file.write("%s0x%016x%s %s\n" % (" .text".ljust(16),m.start,mlen_str.rjust(11),m.name))
		c+=1
		
	file.close()

### NLP Section ###

# This section of code attempts to name the modules based on common strings in the string references
# Not really based on any sound science or anything - your mileage may heavily vary. :-D

#string_range_tokenize(start,end,sep):
#Compile all string references between start and end as a list of strings (called "tokens")
# <sep> should be a nonsense word, and will show up in the list
def string_range_tokenize(start,end,sep):
	# get all string references in this range concatenated into a single string
	t = basicutils.CompileTextFromRange(start,end,sep)
	
	#Enable this if you already have a bunch of function names and want to include that in the mix
	#t+= basicutils.CompileFuncNamesFromRangeAsText(start,end,sep)
	
	#print "string_range_tokenize: raw text:"
	#print t
	#remove printf/sprintf format strings
	tc = re.sub("%[0-9A-Za-z]+"," ",t)
	#convert dash to underscore
	tc = re.sub("-","_",tc)
	#replace _ and / with space - may want to turn this off sometimes
	#this will break up snake case and paths
	#problem is that if you have a path that is used throughout the binary it will probably dominate results
	tc = re.sub("_"," ",tc)
	#replace / and \\ with a space
	tc = re.sub("[/\\\\]"," ",tc)
	#remove anything except alphanumeric, spaces, . (for .c, .cpp, etc) and _
	tc = re.sub("[^A-Za-z0-9_\.\s]"," ",tc)
	
	#lowercase it - and store this as the original set of tokens to work with
	tokens = [tk.lower() for tk in tc.split()]
	
	#remove English stop words
	#this is the list from the MIT *bow project
	eng_stopw = {"about","all","am","an","and","are","as","at","be","been","but","by","can","cannot","did","do","does","doing","done","for","from","had","has","have","having","if","in","is","it","its","of","on","that","the","these","they","this","those","to","too","want","wants","was","what","which","will","with","would"}
	#remove "code" stop words
	#e.g. common words in debugging strings
	code_sw = {"error","err","errlog","log","return","returned","byte","bytes","status","len","length","size","ok","0x","warning","fail","failed","failure","invalid","illegal","param","parameter","done","complete","assert","assertion","cant","didnt","class","foundation","cdecl","stdcall","thiscall"}
	stopw = eng_stopw.union(code_sw)
	c = 0
	
	tokens_f = []
	
	for t in tokens:
		if t not in stopw:
			tokens_f.append(t)
			
	return tokens_f

#bracket_strings(start,end,b_brack,e_brack):
#Return the most common string in the range <star,end> that begins with b_brack and ends with e_brack
#  The count of how many times this string appeared is also returned
#I find somewhat often people format debug strings like "[MOD_NAME] Function X did Y!"
#This function is called by guess_module_names() - if you see this format with different brackets
#you can edit that call
def bracket_strings(start,end,b_brack,e_brack):
	sep = "tzvlw"
	t = basicutils.CompileTextFromRange(start,end,sep)
	tokens = [tk.lower() for tk in t.split(sep)]
	
	b=[]
	for tk in tokens:
		tk = tk.strip()
		
		if tk.startswith(b_brack) :
			b_contents = tk[1:tk.find(e_brack)]
			#Hack to get rid of [-],[+],[*] - could also try to remove non alpha
			if (len(b_contents) > 3):
				b.append(tk[1:tk.find(e_brack)])
			
	#print "bracket_strings tokens:"
	#print tokens
	#print b
	
	u_gram=""
	u_gram_score=0
	if (len(b) > 0):
		f = nltk.FreqDist(b)
		u_gram = f.most_common(1)[0][0]
		u_gram_score = f.most_common(1)[0][1]
		
	return (u_gram,u_gram_score)

#source_file_strings(start,end):
#Return the most common string that looks like a source file name in the given range
#  The count of how many times this string appeared is also returned
def source_file_strings(start,end):
	sep = "tzvlw"
	t = basicutils.CompileTextFromRange(start,end,sep)
	#normally would do lower here to normalize but we lose camel case that way
	tokens = [tk for tk in t.split(sep)]
	
	#for each string, remove quotes and commas, then tokenize based on spaces to generate the final list
	tokens2=[]
	for tk in tokens:
		tk = tk.strip()
		#strip punctuation, need to leave in _ for filenames and / and \ for paths 
		tk = re.sub("[\"\'\,]"," ",tk)
		for tk2 in tk.split(" "):
			tokens2.append(tk2)
	
	b=[]
	for tk in tokens2:
		tk = tk.strip()
		if tk.endswith(".c") or tk.endswith(".cpp") or tk.endswith(".cc"):
			#If there's a dir path, only use the end filename
			#This could be tweaked if the directory structure is part of the software architecture
			#e.g. if there are multiple source directories with meaningful names
			if tk.rfind("/") != -1:
				ntk = tk[tk.rfind("/")+1:]
			elif tk.rfind("\\") != -1:
				ntk = tk[tk.rfind("\\")+1:]
			else:
				ntk = tk
			b.append(ntk)
			
	#print "source_file_strings tokens:"
	#print tokens
	#print b
	
	#a better way to do this (if there are multiple)
	#would be to sort, uniquify, and then make the name foo.c_and_bar.c
	u_gram=""
	u_gram_score=0
	if (len(b) > 0):
		f = nltk.FreqDist(b)
		u_gram = f.most_common(1)[0][0]
		u_gram_score = f.most_common(1)[0][1]
		
	return (u_gram,u_gram_score)
	
#common_strings(start,end):
#Return a list of the common strings in the given range	
#Uses NLTK to generate a list of unigrams, bigrams, and trigrams (1 word, 2 word phrase, 3 word phrase)
#If the trigram score > 1/2 * bigram score, the most common trigram is used
#If the bigram score > 1/2 * unigram score, the most common bigram is used
#Otherwise the most common unigram (single word is used)
def common_strings(start,end):
	CS_THRESHOLD = 6
	sep = "tvlwz"
	
	tokens = string_range_tokenize(start,end,sep)
	
	#make a copy since we're going to edit it
	u_tokens = tokens
	c=0
	while (c<len(u_tokens)):
		if u_tokens[c] == sep:
			del u_tokens[c]
		else:
			c+=1
	
	print "common_strings tokens:"
	print tokens
	
	if len(u_tokens) < CS_THRESHOLD:
		#print "%08x - %08x : %s" % (start,end,"no string")
		return ("",0)	
	
	f = nltk.FreqDist(u_tokens)
	u_gram = f.most_common(1)[0][0]
	u_gram_score = f.most_common(1)[0][1]
	
	#print "Tokens:"
	#print tokens
	#print len(tokens)
	
	bgs = list(nltk.bigrams(tokens))
	c=0
	while (c<len(bgs)):
		if sep in bgs[c]:
			del bgs[c]
		else:
			c+=1
	
	#print "Bigrams:"
	#print bgs
	if (len(bgs) != 0):
		fs = nltk.FreqDist(bgs)
		b_gram = fs.most_common(1)[0][0]
		#print "Most Common:"
		#print b_gram
		b_str = b_gram[0] + "_" + b_gram[1]
		b_gram_score = fs.most_common(1)[0][1]
	else:
		b_str =""
		b_gram_score = 0
		
	tgs = list(nltk.trigrams(tokens))
	c=0
	while (c<len(tgs)):
		if sep in tgs[c]:
			del tgs[c]
		else:
			c+=1
	#print "Trigrams:"
	#print tgs
	if (len(tgs) != 0):
		ft = nltk.FreqDist(tgs)
		t_gram = ft.most_common(1)[0][0]
		t_str = t_gram[0] + "_" + t_gram[1] + "_" + t_gram[2]
		t_gram_score = ft.most_common(1)[0][1]
	else:
		t_str = ""
		t_gram_score = 0
		
	
	#print "1: %s - %d 2: %s - %d 3: %s - %d\n" % (u_gram,u_gram_score,b_str,b_gram_score,t_str,t_gram_score)
	
	if (b_gram_score * 2 >= u_gram_score):
		if (t_gram_score * 2 >= b_gram_score):
			ret = t_str
			ret_s = t_gram_score
		else:
			ret = b_str
			ret_s = b_gram_score
	else:
		ret = u_gram
		ret_s = u_gram_score
	
	#print "%08x - %08x : %s" % (start,end,ret)
	
	return (ret,ret_s)

### End of NLP Section ###	


#func_callers_weight(f):
#Return the LFA score for functions that this functions calls (i.e. the "calls from" score)
#If there are no references, return 0
def func_callers_weight(f):
	fc = 0
	fs = 0
	for xref in basicutils.FuncXrefsFrom(f):
		dist = abs(xref - f)
		#print "%08x:  %08x %d " % (f, xref, dist),
		if dist > MAX_CALL:
			continue
		if (dist != 0):
			logdist = math.log(dist)
		else: #recursive function call
			logdist = 0
		if (xref - f < 0):
			o = -logdist
		else:
			o = logdist
			#print " %f " % o,
		fs += o
		fc += 1

	if fc == 0:
		score = 0
	else:		
		score = fs / fc
	return score

#func_callee_weight(f):
#Return the LFA score for calls where this function is the "callee" (i.e. the "calls to" score)
#If there are no references, return 0
def func_callee_weight(f):
	fc = 0
	fs = 0
	a = 0
	for xref in idautils.CodeRefsTo(f,0):
	
		dist = abs(xref - f)
		#print "%08x:  %08x %d " % (f, xref, dist),
		if dist > MAX_CALL:
			continue
		if (dist != 0):
			logdist = math.log(dist)
		else: #recursive function call
			logdist = 0
		if (xref - f < 0):
			o = -logdist
		else:
			o = logdist
			#print " %f " % o,
		fs += o
		fc += 1

		
	if fc == 0:
		score = 0
	else:		
		score = fs / fc
	return score
	
#func_call_weight(start,end):
#Iterate over each function in the range and calculated the LFA scores
# If both scores are 0, skip the function altogether, exclude it from the list
# If one score is 0, interpolate that score from the previous score	
def func_call_weight(f_start, f_end):
	global g_function_list
	
	c = 1
	f = f_start
	fe = f_end
	
	if f==0:
		f = basicutils.NextFunction(0)
		f_end = basicutils.BADADDR
	
	prevscore = 0
	prevscore_1 = 0
	prevscore_2 = 0
	z1 = 0
	z2 = 0
	
	#for each function in range
	while (f < fe):
		
		#get both LFA scores for the function
		score_1 = func_callers_weight(f)
		score_2 = func_callee_weight(f)

		#if both scores are 0 (i.e. no references for the function or all refs are above the threshold)
		#then skip the function altogether
		if (score_1 == 0) and (score_2 == 0):
			print "Skipping 0x%08x\n" % f
			prevscore_1 = 0
			prevscore_2 = 0
			z1 = 1
			z2 = 1
			f = idc.NextFunction(f)
			continue
		
		#if 1st or 2nd score is zero, interpolate using previous score and an assumed negative linear slope
		#otherwise use the score
		if (score_1 == 0):
			score_1 = prevscore_1 - z1 * .4
			z1 += 1
		else:
			prevscore_1 = score_1
			z1 = 1
		if (score_2 == 0):
			score_2 = prevscore_2 - z2 * .4
			z2 += 1
		else:
			prevscore_2 = score_2
			z2 = 1
		
		total_score = score_1 + score_2
		
		#Output scores in log window
		print "0x%08x, %d , %f, %f, %f" % (f, c,score_1, score_2, total_score)
		
		#Add scores to the global function score list
		finf = func_info(f,score_1,score_2)
		g_function_list.append(finf)
		
		line = "0x%08x, %d , %f, %f, %f\n" % (f,c,score_1, score_2, total_score)
		f=basicutils.NextFunction(f)
		c+=1

#edge_detect():
# Determine boundaries between object files
#  Edge condition is a delta of at least 2 where the current score is positive 
#      and 2 of the last 3 scores were negative (negative trend) 		
def edge_detect():
	global g_function_list
	global g_module_list
	
	#For published research
	EDGE_THRESHOLD = 2
	
	c=3
	#do edge detection
	while (c<len(g_function_list)):
		p_1 = g_function_list[c-1].total_score
		p_2 = g_function_list[c-2].total_score
		p_3 = g_function_list[c-3].total_score
		s = g_function_list[c].total_score
		#if score is positive and it is diff of at least 2 from previous
		#and the previous function was not an edge
		if ((not g_function_list[c-1].edge == 1) and (s > 0) and ((s - p_1) > EDGE_THRESHOLD)):
			#if 2 of last 3 were negative
			m = sorted([p_1,p_2,p_3])
			if (m[1] < 0):
				g_function_list[c].edge=1
		c+=1
	#assign modules based on where the edges are
	c=0
	mod_start = g_function_list[0].loc
	while(c<len(g_function_list)):
		f = g_function_list[c]
		if (f.edge == 1):
			p = g_function_list[c-1]
			b_mod = bin_module(mod_start,p.loc,0,"")
			mod_start = f.loc
			g_module_list.append(b_mod)
		c+=1

#guess_module_names():
#Use the NLP section (above) to guess the names of modules and add them to the global module list
#Attempts to find common bracket strings (e.g. "[MOD_NAME] Debug print!")
#then source file names (most often left over from calls to assert())
#then common trigram/bigram/unigrams
#You can tweak the switchover thresholds below.
def guess_module_names():
	#idea - make score threshold based on the size of the module
	# (e.g. smaller modules should have a smaller threshold
	global g_module_list
	C_SCORE_THRESHOLD = 3
	S_SCORE_THRESHOLD = 1
	B_SCORE_THRESHOLD = 1
	c=0
	unk_mod=0
	while (c<len(g_module_list)):
		m = g_module_list[c]
		# first look for strings that start with [FOO], (bracket strings)
		# then look for strings that contain source files (.c,.cpp,etc.)
		# then try common strings
		# above thresholds can be tweaked - they represent the number of strings that have to be repeated
		# in order to use that string as the module name
		(name,scr) = bracket_strings(m.start,m.end,"[","]")
		if (scr < B_SCORE_THRESHOLD):
			(name,scr) = source_file_strings(m.start,m.end)
			if (scr < S_SCORE_THRESHOLD):
				(name,scr) = common_strings(m.start,m.end)
				if (scr < C_SCORE_THRESHOLD):
					#Couldn't come up with a name so name it umod1, umod2, etc.
					name = "umod%d" % (unk_mod)
					#"word cloud" or something to get an idea of what the module is
					#print basicutils.CompileTextFromRange(m.start,m.end," ")
					unk_mod+=1
		g_module_list[c].name = name
		g_module_list[c].score = scr
		print "%08x - %08x : %s (%d)" % (m.start,m.end,name,scr)
		c+=1
		
#print_results():
#Write all of the results to <target>.csv - which can be opened in your favorite spreadsheet program		
def print_results():
	global g_function_list
	c=0
	root_name = basicutils.GetInputFile()
	file = open(root_name + "_lfa_results.csv", "wb")
	
	#write header
	file.write("Function,Function #,Score 1,Score 2,Total,Edge,Function Name,Suggested Module Name\n");
	
	while (c<len(g_function_list)):
		f = g_function_list[c]
		fname = basicutils.GetFunctionName(f.loc)
		m = locate_module(f.loc)
		mname = m.name 
		line = "0x%08x, %d , %f, %f, %f, %d, %s, %s\n" % (f.loc,c+1,f.score1, f.score2, f.total_score,f.edge, fname, mname)
		file.write(line)
		c+=1
	
def go():

	#Define range to analyze
	#just do .text segment if we've got one
	#otherwise just start from the first function in DB
	start,end = basicutils.SegByName(".text")
	if (start == basicutils.BADADDR):
		start = basicutils.NextFunction(0)
		end = basicutils.BADADDR
	
	#Calculate LFA score for all functions
	func_call_weight(start,end)
	#Detect edges - object file boundaries
	edge_detect()
	#Guess names for the modules using NLP
	guess_module_names()
	#Output all results as .csv
	print_results()
	#Output module-to-module call graph as a Graphviz .gv file
	gen_mod_graph()
	#Output a Python script that will rename modules
	gen_rename_script()
	#Output .map file (for comparison against ground truth, when available)
	gen_map_file()

	return True

if __name__ == "__main__":
	reload(basicutils)
	go()