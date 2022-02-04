from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.decompiler import DecompileOptions, DecompInterface

# == helper functions =============================================================================
def get_high_function(func):
    options = DecompileOptions()
    monitor = ConsoleTaskMonitor()
    ifc = DecompInterface()
    ifc.setOptions(options)
    ifc.openProgram(getCurrentProgram())
    # Setting a simplification style will strip useful `indirect` information.
    # Please don't use this unless you know why you're using it.
    #ifc.setSimplificationStyle("normalize") 
    res = ifc.decompileFunction(func, 60, monitor)
    high = res.getHighFunction()
    return high

def dump_refined_pcode(func, high_func):
    opiter = high_func.getPcodeOps()
    while opiter.hasNext():
        op = opiter.next()
        print("{}".format(op.toString()))
	if op.getOutput():
		print("Output Addr {}".format(op.getOutput().getUniqueId()))
		pass
	for i in range(op.getNumInputs()):
        	vn = op.getInput(i)
                if vn:
                	print("VN Info {}".format(vn.getUniqueId()))
			#print("VN Info {}".format(vn.getAddress()))
			#print("VN Name {}".format(vn.getAddress().toString(True)))
			pass
                        
        
# == run examples =================================================================================
def getAddress(offset):
    return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset)
func = currentProgram.getListing().getFunctionContaining(getAddress(0x200077E4))
hf = get_high_function(func)            # we need a high function from the decompiler
dump_refined_pcode(func, hf)            # dump straight refined pcode as strings