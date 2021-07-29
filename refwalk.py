import draw_graph

def shouldCall(address, ref):
	called_func_offset = ref.getToAddress().getOffset()
	printd("From 0x{0:x} -> To 0x{1:x}".format(address.getOffset() ,called_func_offset))
	if address.getOffset()  == called_func_offset:
		return False
	elif(hex(called_func_offset) not in stack):
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
		text = text.toString()
	with open('output_trace.txt', 'a') as output:
		output.write(text+'\n')

func_refs_dict = {}
stack = []
graph = draw_graph.create_graph()

def should_add_peripheral(next):
	return next >= 0x40000000

def getPeripheralRefs(address, func_pref_seq, refMgr, listing, address_offset):
	toAddressRefs = refMgr.getReferencesFrom(address)
	if len(toAddressRefs) > 0:
		for i in toAddressRefs:
			if i.getToAddress().getOffset() != i.getFromAddress().getOffset():
				getPeripheralRefs(i.getToAddress(), func_pref_seq, refMgr, listing, address_offset)
	else:
		codeUnit = listing.getCodeUnitAt(address)
		
		if(codeUnit == None):
			if should_add_peripheral(address.getOffset()):
				func_pref_seq.append(hex(address.getOffset()))
				graph.add_edge(address_offset, address.getOffset())
		elif(codeUnit.getScalar(0) != None):
			pass
			#should_add_peripheral(codeUnit.getScalar(0))
		elif(codeUnit.getMnemonicString() == "??" or codeUnit.getMnemonicString().startswith("undefined")):
			if should_add_peripheral(address.getOffset()):
				func_pref_seq.append(hex(address.getOffset()))
				graph.add_edge(address_offset, address.getOffset())


def getFuncReferences(address, listing, refMgr):
	
	address_offset = address.getOffset()
	stack.append(hex(address_offset))
	func_periphs = []
	
	func = listing.getFunctionContaining(address)
	graph.add_node(address_offset)
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
				graph.add_node(called_func_addr.getOffset())
				graph.add_edge(address_offset, called_func_addr.getOffset()) 
				if shouldCall(address, i):
					func_periphs += getFuncReferences(called_func_addr, listing, refMgr)
				elif(hex(called_func_offset) in func_refs_dict):
					print("We already cached {0:x}".format(called_func_offset))
					func_periphs += func_refs_dict[hex(called_func_offset)]	
			elif (i.getReferenceType().isRead() or i.getReferenceType().isWrite() or i.getReferenceType() == "PARAM"):
				getPeripheralRefs(called_func_addr, func_periphs, refMgr, listing, address_offset)

	if hex(address_offset) not in func_refs_dict:
		func_refs_dict[hex(address_offset)] = func_periphs
	stack.pop()

	
	graph.layout()
	graph.draw("result.png")
	return func_periphs
