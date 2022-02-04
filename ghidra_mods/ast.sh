#!/bin/bash

headless=/Users/wamuo/Documents/Lab/tools/ghidra_10.1-BETA_PUBLIC/support/analyzeHeadless
proj_loc=/Users/wamuo/Documents/Lab/Projects/ghidra_proj
script_fold=/Users/wamuo/Documents/Lab/Projects/FunctionPeripheralSequence/ghidra_mods/
script=/Users/wamuo/Documents/Lab/Projects/FunctionPeripheralSequence/ghidra_mods/GenerateFuncAST.java

update_files=/Users/wamuo/Documents/Lab/Projects/FunctionPeripheralSequence/versions/*.bin

$headless $proj_loc Evolution -process $1 -scriptPath $script_fold -postScript $script $2 $3 -noanalysis -readOnly


