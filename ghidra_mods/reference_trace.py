import sys
import os
import json
import re


import refwalk


program_file = getProgramFile().getName()

def get_valid_filename(s):
    s = str(s).strip().replace('.', '_')
    return re.sub(r'(?u)[^-\w.]', '', s)

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


print("Fetching Info_Graph for: ", program_file)
# sequence = refwalk.getFuncReferences(currentAddress, listing, refMgr)
func_graph = refwalk.get_all_func_props(currentProgram, listing, refMgr)
# func_graph = refwalk.get_all_func_peripherals(currentProgram,listing, func_graph, refMgr)
func_graph = refwalk.get_all_func_instructions(listing, func_graph, currentProgram)
func_graph = refwalk.get_all_func_blocks(currentProgram, listing, func_graph)
func_graph = refwalk.get_all_func_end(currentProgram, listing, func_graph)

# refwalk.printd(func_graph)
 

args = getScriptArgs()
cwd = args[0]


folder = cwd +"/versions/"+ get_valid_filename(program_file) + "/"
if not os.path.exists(folder):
    os.makedirs(folder)
file_name = os.path.join(folder, 'info_graph.json')

with open(file_name, "w") as outfile: 
    json.dump(func_graph, outfile)

print("Fetching Info_Graph Complete")

