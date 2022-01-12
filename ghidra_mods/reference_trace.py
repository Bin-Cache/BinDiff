import sys
import os
import json

import refwalk


try:
    if currentAddress:
        pass
except NameError:
    print("currentAddress is not defined (we are probably outside of Ghidra)")
    import mock_ghidra
    currentAddress = mock_ghidra.getCurrentAddress()

try:
    if currentProgram:
        pass
except NameError:
    print("currentProgram is not defined (we are probably outside of Ghidra)")
    currentProgram = mock_ghidra.getCurrentProgram()


listing = currentProgram.getListing()
refMgr = currentProgram.getReferenceManager()
# functionManager = currentProgram.getFunctionManager()


print("start")
# sequence = refwalk.getFuncReferences(currentAddress, listing, refMgr)
func_graph = refwalk.get_all_func_props(currentProgram, listing, refMgr)
# func_graph = refwalk.get_all_func_peripherals(currentProgram,listing, func_graph, refMgr)
func_graph = refwalk.get_all_func_instructions(listing, func_graph, currentProgram)
func_graph = refwalk.get_all_func_blocks(currentProgram, listing, func_graph)
func_graph = refwalk.get_all_func_end(currentProgram, listing, func_graph)

refwalk.printd(func_graph)
 

try:
    folder = os.path.dirname(os.path.abspath(__file__))
except NameError:
    folder = "/Users/wamuo/Documents/Lab/Projects/FunctionPeripheralSequence/"

out_file = os.environ.get("OUT_FILE", None)
if out_file:
    file_name = os.path.join(folder, out_file)
else:
    file_name = os.path.join(folder, 'graphA.json')

with open(file_name, "w") as outfile: 
    json.dump(func_graph, outfile)
