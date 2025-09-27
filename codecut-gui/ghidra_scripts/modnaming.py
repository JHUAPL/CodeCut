##############################################################################################
# Copyright 2022 The Johns Hopkins University Applied Physics Laboratory LLC
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
#
# This material is based upon work supported by the Defense Advanced Research
# Projects Agency (DARPA) and Naval Information Warfare Center Pacific (NIWC Pacific)
# under Contract Number N66001-20-C-4024.
#

import sys
print(sys.executable)

import sys
import math
import nltk
import nltk.collocations
import re

#uncomment "print" to get debug prints
def debug_print(x):
        #print(x)
        return

### NLP Section ###

# This section of code attempts to name the modules based on common strings in the string references
# Not really based on any sound science or anything - your mileage may heavily vary. :-D

#string_range_tokenize(t):
#Take a long string and convert it into a list of tokens.  If using a separator, this will appear in the token list
def string_range_tokenize(t):
    
    #print "string_range_tokenize: raw text:"
    #print t
    #remove printf/sprintf format strings
    #tc = re.sub("%[0-9A-Za-z]+"," ",t)
    #convert dash to underscore
    #tc = re.sub("-","_",tc)
    #replace _ and / with space - may want to turn this off sometimes
    #this will break up snake case and paths
    #problem is that if you have a path that is used throughout the binary it will probably dominate results
    #tc = re.sub("_"," ",tc)
    #replace / and \\ with a space
    #tc = re.sub("[/\\\\]"," ",tc)
    #remove anything except alphanumeric, spaces, . (for .c, .cpp, etc) and _
    #tc = re.sub("[^A-Za-z0-9_\.\s]"," ",tc)
    
    #lowercase it - and store this as the original set of tokens to work with
    tokens = [tk.lower() for tk in t.split()]
    
    #remove English stop words
    #this is the list from the MIT *bow project
    eng_stopw = {"about","all","am","an","and","are","as","at","be","been","but","by","can","cannot","did","do","does","doing","done","for","from","had","has","have","having","if","in","is","it","its","of","on","that","the","these","they","this","those","to","too","want","wants","was","what","which","will","with","would"}
    #remove "code" stop words
    #e.g. common words in debugging strings
    code_sw =  {"error","err","errlog","log","return","returned","byte","bytes","status","len","length","size","ok","0x","warning","fail","failed","failure","invalid","illegal","param","parameter","done","complete","assert","assertion","cant","didnt","class","foundation","cdecl","stdcall","thiscall"}
    #remove code stop words (from Joxean Koret's "IDAMagicStrings")    
    jk_sw = {"copyright", "char", "bool", "int", "unsigned", "long",
  "double", "float", "signed", "license", "version", "cannot", "error",
  "invalid", "null", "warning", "general", "argument", "written", "report",
  "failed", "assert", "object", "integer", "unknown", "localhost", "native",
  "memory", "system", "write", "read", "open", "close", "help", "exit", "test",
  "return", "libs", "home", "ambiguous", "internal", "request", "inserting",
  "deleting", "removing", "updating", "adding", "assertion", "flags",
  "overflow", "enabled", "disabled", "enable", "disable", "virtual", "client",
  "server", "switch", "while", "offset", "abort", "panic", "static", "updated",
  "pointer", "reason", "month", "year", "week", "hour", "minute", "second", 
  'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday',
  'january', 'february', 'march', 'april', 'may', 'june', 'july', 'august',
  'september', 'october', 'november', 'december', "arguments", "corrupt", 
  "corrupted", "default", "success", "expecting", "missing", "phrase", 
  "unrecognized", "undefined"}

    stopw = eng_stopw.union(code_sw)
    stopw = stopw.union(jk_sw)

    c = 0
    
    tokens_f = []
    
    for t in tokens:
        if t not in stopw:
            tokens_f.append(t)
            
    return tokens_f

#bracket_strings(t,b_brack,e_brack):
#Return the most common string in the text that begins with b_brack and ends with e_brack
#  The count of how many times this string appeared is also returned
#I find somewhat often people format debug strings like "[MOD_NAME] Function X did Y!"
#This function is called by guess_module_names() - if you see this format with different brackets
#you can edit that call
def bracket_strings(t, b_brack,e_brack, sep):
    #sep = "tzvlw"
    #t = basicutils.CompileTextFromRange(start,end,sep)
    tokens = [tk.lower() for tk in t.split(sep)]
    #don't want to use tokenize here because it removes brackets
    
    b=[]
    for tk in tokens:
        tk = tk.strip()
        
        if tk.startswith(b_brack):
            b_contents = tk[1:tk.find(e_brack)] if e_brack in tk else tk[1:]
            #print("found bracket string, content: %s" % b_contents)
            #Hack to get rid of [-],[+],[*] - could also try to remove non alpha
            if (len(b_contents) > 3):
                #Hack for debug prints that started with [0x%x]
                if (b_contents != "0x%x"):
                    b.append(b_contents)
            
    debug_print("bracket_strings tokens:")
    debug_print(tokens)
    debug_print(b)
    
    u_gram=""
    u_gram_score=0
    if (len(b) > 0):
        f = nltk.FreqDist(b)
        u_gram = f.most_common(1)[0][0]
        u_gram_score = f.most_common(1)[0][1]
        
    return (u_gram,u_gram_score)

#is_source_file_str(f):
#return True if the file string ends with one of the source file extensions
#This uses structure borrowed from Joxean Koret's IDAMagicStrings
LANGS = {}
LANGS["C/C++"] = ["c", "cc", "cxx", "cpp", "h", "hpp"]
LANGS["C"] = ["c"]
LANGS["C++"] = ["cc", "cxx", "cpp", "hpp", "c++"]
LANGS["Obj-C"] = ["m"]
LANGS["Rust"] = ["rs"]
LANGS["Golang"] = ["go"]
LANGS["OCaml"] = ["ml"]
def is_source_file_str(f):
        for key in LANGS:
                for ext in LANGS[key]:
                        if f.endswith("." + ext):
                                return True
        return False


#source_file_strings(start,end):
#Return the most common string that looks like a source file name in the given text string
#  The count of how many times this string appeared is also returned
def source_file_strings(t, sep):
    #sep = "tzvlw"
    #t = basicutils.CompileTextFromRange(start,end,sep)
    #normally would do lower here to normalize but we lose camel case that way
    tokens = [tk for tk in t.split(sep)]
    
    #for each string, remove quotes and commas, then tokenize based on spaces to generate the final list
    tokens2=[]
    for tk in tokens:
        tk = tk.strip()
        #strip punctuation, need to leave in _ for filenames and / and \ for paths 
        tk = re.sub("[\"\',]"," ",tk)
        for tk2 in tk.split(" "):
            tokens2.append(tk2)

    debug_print("source_file_strings tokens2:")
    debug_print(tokens2)    

    b=[]
    for tk in tokens2:
        tk = tk.strip()
        if is_source_file_str(tk):
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
            
    debug_print("source_file_strings tokens:")
    debug_print(tokens)
    debug_print(b)
    
    #a better way to do this (if there are multiple)
    #would be to sort, uniquify, and then make the name foo.c_and_bar.c
    u_gram=""
    u_gram_score=0
    if (len(b) > 0):
        f = nltk.FreqDist(b)
        u_gram = f.most_common(1)[0][0]
        u_gram_score = f.most_common(1)[0][1]
        
    return (u_gram,u_gram_score)
    
#common_strings(t, sep):
#Return a list of the common strings in the string "t" - lines separated by "sep"
#Uses NLTK to generate a list of unigrams, bigrams, and trigrams (1 word, 2 word phrase, 3 word phrase)
#If the trigram score > 1/2 * bigram score, the most common trigram is used
#If the bigram score > 1/2 * unigram score, the most common bigram is used
#Otherwise the most common unigram (single word is used)
def common_strings(t,sep):
    CS_THRESHOLD = 6
    
    tokens = string_range_tokenize(t)
    
    #make a copy since we're going to edit it
    u_tokens = tokens
    c=0
    while (c<len(u_tokens)):
        if u_tokens[c] == sep:
            del u_tokens[c]
        else:
            c+=1
    
    debug_print("common_strings tokens:")
    debug_print(tokens)
    
    if len(u_tokens) < CS_THRESHOLD:
        #print("less than threshold")
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
    
    debug_print("Bigrams:")
    debug_print(bgs)
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
    debug_print("Trigrams:")
    debug_print(tgs)
    if (len(tgs) != 0):
        ft = nltk.FreqDist(tgs)
        t_gram = ft.most_common(1)[0][0]
        t_str = t_gram[0] + "_" + t_gram[1] + "_" + t_gram[2]
        t_gram_score = ft.most_common(1)[0][1]
    else:
        t_str = ""
        t_gram_score = 0
        
    
    debug_print("1: %s - %d 2: %s - %d 3: %s - %d\n" % (u_gram,u_gram_score,b_str,b_gram_score,t_str,t_gram_score))
    
    if (b_gram_score > 1) and (b_gram_score * 2 >= u_gram_score):
        if (t_gram_score > 1) and (t_gram_score * 2 >= b_gram_score):
            ret = t_str
            ret_s = t_gram_score
        else:
            ret = b_str
            ret_s = b_gram_score
    else:
        ret = u_gram
        ret_s = u_gram_score
    
    return (ret,ret_s)

### End of NLP Section ###    



#guess_module_names():
#Use the NLP section (above) to guess the names of modules and add them to the global module list
#Attempts to find common bracket strings (e.g. "[MOD_NAME] Debug print!")
#then source file names (most often left over from calls to assert())
#then common trigram/bigram/unigrams
#You can tweak the switchover thresholds below.

def guess_module_names(t,sep):
    #idea - make score threshold based on the size of the module
    # (e.g. smaller modules should have a smaller threshold
    C_SCORE_THRESHOLD = 4 #we need to see at least <N> occurrences of a string set in order to pick that name
    S_SCORE_THRESHOLD = 2 #if we see <N> occurrences of foo.c we'll pick "foo.c"
    B_SCORE_THRESHOLD = 2 #if we see <N> occurrences of [foo] we'll pick "foo"

        # first look for strings that start with [FOO], (bracket strings)
        # then look for strings that contain source files (.c,.cpp,etc.)
        # then try common strings
        # above thresholds can be tweaked - they represent the number of strings that have to be repeated
        # in order to use that string as the module name
    (name,scr) = bracket_strings(t,"[","]",sep)
    debug_print("bracket name: %s score: %d" %(name, scr))
    #if (True):
    if (scr < B_SCORE_THRESHOLD):        
        (name,scr) = source_file_strings(t,sep)
        debug_print("source name: %s score: %d" % (name, scr))
        #if (True):e
        if (scr < S_SCORE_THRESHOLD):            
            (name,scr) = common_strings(t,sep)
            debug_print("common name: %s score: %d" % (name, scr))
            if (scr < C_SCORE_THRESHOLD):
                #Couldn't come up with a name
                name = "unknown"

    return name

def main():
    #t=""
    sep = "tzvlw"
    # java side handles adding sep between strings,
    # read all in at once (no newlines between strings)
    #t = sys.stdin.readline()
    t = input()
    #print ("text in: %s" % t)
    name = guess_module_names(t,sep)
    print(name)


if __name__ == "__main__":
    main()
