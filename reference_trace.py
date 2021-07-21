import sys
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
print(func_graph )
sequence = refwalk.getFuncReferencesQueue(currentAddress, func_graph)
print(len(sequence))
print(sequence)
