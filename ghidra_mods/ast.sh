#!/bin/bash

if [[ -z ${GHIDRA_HEADLESS+x} || ! -f "$GHIDRA_HEADLESS" ]];
then
    echo "ERROR: Unable to process this task. Please set the bash variable for GHIDRA_HEADLESS path"
    exit 1
fi


proj_loc="${1}/ghidra_mods/ghidra_proj"
script_fold="${1}/ghidra_mods/"
script="${1}/ghidra_mods/GenerateFuncAST.java"


$GHIDRA_HEADLESS $proj_loc Evolution -process $2 -scriptPath $script_fold -postScript $script $1 $3 $4 -noanalysis -readOnly


