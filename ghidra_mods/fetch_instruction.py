def getAddress(offset):
    return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset)


args = getScriptArgs()

instruction = currentProgram.getListing().getInstructionAt(getAddress(args[0]))

if instruction:
    prev = instruction.getPrevious().toString()
    next = instruction.getNext().toString()
    instruction_string = instruction.toString()

    print(prev, instruction_string, next)
    text_file = open("temp", "w")
    text_file.write(instruction_string)
    text_file.close()
else:
    instruction_string = ""
    text_file = open("temp", "w")
    text_file.write(instruction_string)
    text_file.close()
