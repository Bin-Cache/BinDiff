#!/bin/bash

headless=/Users/wamuo/Documents/Lab/tools/ghidra_10.1-BETA_PUBLIC/support/analyzeHeadless
proj_loc=/Users/wamuo/Documents/Lab/Projects/ghidra_proj
script_fold=/Users/wamuo/Documents/Lab/Projects/FunctionPeripheralSequence/ghidra_mods/
script=/Users/wamuo/Documents/Lab/Projects/FunctionPeripheralSequence/ghidra_mods/reference_trace.py

update_files=/Users/wamuo/Documents/Lab/Projects/FunctionPeripheralSequence/versions/*.bin


$headless $proj_loc Evolution -import $update_files -loader BinaryLoader -loader-baseAddr 0x20004000 -loader-blockName app -processor ARM:LE:32:Cortex
$headless $proj_loc Evolution -process "*.bin" -scriptPath $script_fold -postScript $script -noanalysis -readOnly


# OUT_FILE='graphA.json' $headless $proj_loc 'ARM Galore' -process otaApp-1.4.2.bin -scriptPath $script_fold -postScript $script -noanalysis -readOnly
# OUT_FILE='graphB.json' /Users/wamuo/Documents/Lab/tools/ghidra_9.2/support/analyzeHeadless /Users/wamuo/Documents/Lab/Projects/ghidra_proj 'ARM Galore' -process otaApp-1.4.4.bin -scriptPath /Users/wamuo/Documents/Lab/Projects/FunctionPeripheralSequence -postScript reference_trace.py -noanalysis -readOnly

# OUT_FILE='graphB.json' /Users/wamuo/Documents/Lab/tools/ghidra_9.2/support/analyzeHeadless /Users/wamuo/Documents/Lab/Projects/ghidra_proj 'ARM Galore' -process http_client_demo1_1.bin -scriptPath /Users/wamuo/Documents/Lab/Projects/FunctionPeripheralSequence -postScript reference_trace.py -noanalysis -readOnly

# python compare.py
