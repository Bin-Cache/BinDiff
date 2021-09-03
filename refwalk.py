try:
   from queue import Queue
except ImportError:
   from Queue import Queue


def getAddress(currentProgram, offset):
    return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset)

def shouldCall(address, ref):
    called_func_offset = ref.getToAddress().getOffset()
    printd("From 0x{0:x} -> To 0x{1:x}".format(address.getOffset() ,called_func_offset))
    if address.getOffset()  == called_func_offset:
        return False
    elif(called_func_offset not in stack):
        if(hex(called_func_offset) in func_refs_dict):
            return False
        else:
            return True
    else:
        printd("Recursion on " + hex(called_func_offset))
        printd("I think i've seen 0x{0:x} before. Stack: {1}".format(called_func_offset ,str(stack)))
        return False

def printd(text):
    print(text)
    if type(text) != str:
        return
    with open('output_trace.txt', 'a') as output:
        output.write(text+'\n')


func_refs_dict = {}
stack = []

def should_add_peripheral(next):
    return next >= 0x40000000 and next <= 0x60000000

def getPeripheralRefs(address, func_pref_seq, refMgr, listing):
    toAddressRefs = refMgr.getReferencesFrom(address)
    if len(toAddressRefs) > 0:
        for i in toAddressRefs:
            if i.getToAddress().getOffset() != i.getFromAddress().getOffset():
                getPeripheralRefs(i.getToAddress(), func_pref_seq, refMgr, listing)
    else:
        codeUnit = listing.getCodeUnitAt(address)
        
        if(codeUnit == None):
            if should_add_peripheral(address.getOffset()):
                func_pref_seq.append(hex(address.getOffset()))
        elif(codeUnit.getScalar(0) != None):
            pass
            #should_add_peripheral(codeUnit.getScalar(0))
        elif(codeUnit.getMnemonicString() == "??" or codeUnit.getMnemonicString().startswith("undefined")):
            if should_add_peripheral(address.getOffset()):
                func_pref_seq.append(hex(address.getOffset()))


def getFuncReferences(address, listing, refMgr):
    
    address_offset = address.getOffset()

    stack.append(address_offset)
    func_periphs = []
    
    func = listing.getFunctionContaining(address)
    if (func == None):
        printd("No Function at address " + address.toString())
        return
    func_addresses = func.getBody().getAddresses(True)
    
    for func_address in func_addresses:
        references = refMgr.getReferencesFrom(func_address)
        for i in references:
            called_func_addr = i.getToAddress()
            called_func_offset = called_func_addr.getOffset()
            if i.getReferenceType().isCall():
                if shouldCall(address, i):
                    result = getFuncReferences(called_func_addr, listing, refMgr)
                    if result:
                        func_periphs += result    
                elif(hex(called_func_offset) in func_refs_dict):
                    printd("We already cached {0:x}".format(called_func_offset))
                    func_periphs += func_refs_dict[hex(called_func_offset)]	
            elif (i.getReferenceType().isRead() or i.getReferenceType().isWrite() or i.getReferenceType() == "PARAM"):
                getPeripheralRefs(called_func_addr, func_periphs, refMgr, listing)

    if hex(address_offset) not in func_refs_dict:
        func_refs_dict[hex(address_offset)] = func_periphs
    stack.pop()

    return func_periphs


def getFuncReferencesQueue(function_addr, func_graph):
    func_periphs = []
    q = Queue()
    seen = set()
    func_offset = hex(function_addr.getOffset()).rstrip("L")
    q.put(func_offset)
    while(not q.empty()):
        current_addr = q.get()
        if(current_addr not in seen):
            seen.add(current_addr)
            func_periphs.extend(func_graph[current_addr][1])
        
        for child in func_graph[current_addr][0]:
            if(child not in seen):
                q.put(child)

    return func_periphs

def get_func_props(func, refMgr, listing):
    child_funcs = []
    func_periphs = []
    func_addresses = func.getBody().getAddresses(True)
    for func_address in func_addresses:
        references = refMgr.getReferencesFrom(func_address)
        for i in references:
            if i.getReferenceType().isCall():
                if i.getToAddress().getOffset() != i.getFromAddress().getOffset():
                    child_funcs.append(hex(i.getToAddress().getOffset()).rstrip("L"))
            elif (i.getReferenceType().isRead() or i.getReferenceType().isWrite() or i.getReferenceType() == "PARAM"):
                getPeripheralRefs(i.getToAddress(), func_periphs, refMgr, listing)
    return (child_funcs, func_periphs)


def get_all_func_props(currentProgram, listing, refMgr):
    func_graph = {}
    fm = currentProgram.getFunctionManager()
    funcs = fm.getFunctions(True)
    for func in funcs:
        func_graph[hex(int(func.getEntryPoint().getOffset()))] = get_func_props(func, refMgr, listing)
    return func_graph

def get_all_func_peripherals(currentProgram, listing, func_graph, refMgr):  
    for func_address in func_graph:
       func_graph[func_address] = (func_graph[func_address][0], getFuncReferences(getAddress(currentProgram, func_address), listing, refMgr))
    return func_graph

def get_all_func_instructions(listing, func_graph, currentProgram):  
    for func_address in func_graph:
        func = listing.getFunctionContaining(getAddress(currentProgram,func_address))
        func_addresses = func.getBody().getAddresses(True)
        instructions = ""
        for instr_address in func_addresses:
            instruction = listing.getInstructionAt(instr_address)
            if instruction:
                instruction_string = instruction.toString()
                instructions += " " + instruction_string
            else:
                print(instr_address)
          

        print(instructions)
            
        func_graph[func_address] = (func_graph[func_address][0], func_graph[func_address][1], instructions)
    return func_graph
