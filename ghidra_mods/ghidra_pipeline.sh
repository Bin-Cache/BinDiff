#!/bin/bash

if [[ -z ${GHIDRA_HEADLESS+x} || ! -f "$GHIDRA_HEADLESS" ]];
then
    echo "ERROR: Unable to process this task. Please set the bash variable for GHIDRA_HEADLESS path"
    exit 1
fi


proj_loc="${1}/ghidra_mods/ghidra_proj"
script_fold="${1}/ghidra_mods/"
script="${1}/ghidra_mods/reference_trace.py"

update_files="${1}/versions/*.bin"


$GHIDRA_HEADLESS $proj_loc Evolution -import $update_files -loader BinaryLoader -loader-baseAddr $2 -loader-blockName app -processor ARM:LE:32:Cortex
$GHIDRA_HEADLESS $proj_loc Evolution -process "*.bin" -scriptPath $script_fold -postScript $script $1 -noanalysis -readOnly


