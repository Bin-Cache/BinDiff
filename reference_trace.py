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
sys.setrecursionlimit(15000)
refwalk.getFuncReferences(currentAddress, {}, listing, refMgr)
print(refwalk.sequence)
