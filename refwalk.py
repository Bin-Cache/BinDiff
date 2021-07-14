def shouldCall(address, ref):
	calledFunc = ref.getToAddress().getOffset()
	callingFunc = ref.getFromAddress().getOffset()
	printd("From 0x{0:x} -> To 0x{1:x}".format(address.getOffset() ,calledFunc))
	if address.getOffset()  == calledFunc:
		printd("Recursion?")
		return False
	else:
		return True


def printd(text):
	print(text)
	if type(text) != str:
		text = text.toString()
	with open('output_trace.txt', 'a') as output:
		output.write(text+'\n')

sequence = []
stack = []
def addSeq(next):
	#print(hex(next))
	if next > 0x40000000:
		sequence.append(hex(next))


def getPeripheralRefs(address, refMgr, listing):
	toAddressRefs = refMgr.getReferencesFrom(address)
	if len(toAddressRefs) > 0:
		for i in toAddressRefs:
			if i.getToAddress().getOffset() != i.getFromAddress().getOffset():
				getPeripheralRefs(i.getToAddress(), refMgr, listing)
	else:
		codeUnit = listing.getCodeUnitAt(address)
		
		if(codeUnit == None):
			addSeq(address.getOffset())
		elif(codeUnit.getScalar(0) != None):
			pass
			#addSeq(codeUnit.getScalar(0))
		elif(codeUnit.getMnemonicString() == "??" or codeUnit.getMnemonicString().startswith("undefined")):
			addSeq(address.getOffset())


def getFuncReferences(address, listing, refMgr):
	
	stack.append(hex(address.getOffset()))
	
	func = listing.getFunctionContaining(address)
	if (func == None):
		printd("No Function at address " + address.toString())
		return
	func_addresses = func.getBody().getAddresses(True)
	
	for func_address in func_addresses:
		references = refMgr.getReferencesFrom(func_address)
		for i in references:
			if i.getReferenceType().isCall():
				if shouldCall(address, i):
					if(stack.count(hex(address.getOffset())) < 2):
						getFuncReferences(i.getToAddress(), listing, refMgr)
					else:
						printd("Recursion on " + hex(address.getOffset()))
						printd("I think i've seen 0x{0:x} before. Stack: {1}".format(address.getOffset() ,str(stack)))

			elif (i.getReferenceType().isRead() or i.getReferenceType().isWrite() or i.getReferenceType() == "PARAM"):
				getPeripheralRefs(i.getToAddress(), refMgr, listing)

	stack.pop()