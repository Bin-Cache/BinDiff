import sys

listing = currentProgram.getListing()
refMgr = currentProgram.getReferenceManager()
functionManager = currentProgram.getFunctionManager()

sequence = []


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

def addSeq(next):
	#print(hex(next))
	if next > 0x40000000:
		sequence.append(hex(next))


def getPeripheralRefs(address):
	toAddressRefs = refMgr.getReferencesFrom(address)
	if len(toAddressRefs) > 0:
		for i in toAddressRefs:
			printd(i)
			if i.getToAddress().getOffset() != i.getFromAddress().getOffset():
				getPeripheralRefs(i.getToAddress())
	else:
		codeUnit = listing.getCodeUnitAt(address)
		
		if(codeUnit == None):
			addSeq(address.getOffset())
		elif(codeUnit.getScalar(0) != None):
			pass
			#addSeq(codeUnit.getScalar(0))
		elif(codeUnit.getMnemonicString() == "??" or codeUnit.getMnemonicString().startswith("undefined")):
			addSeq(address.getOffset())


def getFuncReferences(address):
	func = listing.getFunctionContaining(address)
	if (func == None):
		print("No Function at address " + address.toString())
		return
	func_addresses = func.getBody().getAddresses(True)
	
	for func_address in func_addresses:
		references = refMgr.getReferencesFrom(func_address)
		for i in references:
			if i.getReferenceType().isCall():
				if shouldCall(address,i):
					getFuncReferences(i.getToAddress())
			elif (i.getReferenceType().isRead or i.getReferenceType().isWrite() or i.getReferenceType() == "PARAM"):
				printd(i)
				getPeripheralRefs(i.getToAddress())
						
print("start")
sys.setrecursionlimit(15000)
getFuncReferences(currentAddress)
print(sequence)