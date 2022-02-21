def getAddress(offset):
    return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset)


instruction = currentProgram.getListing().getInstructionAt(getAddress(0x2000b9b8))

if instruction:
    instruction_pcode = instruction.getPcode()
    
    for op in instruction_pcode:
        print("{}".format(op.toString()))

else:
    instruction_string = ""
    print("Not found")
