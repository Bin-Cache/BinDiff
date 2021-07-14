import sys
import os
import json

graph = {}

def getCurrentAddress():
    return Address(1)

class Program():
    def getListing(self):
        test_case = os.environ.get("TEST_CASE", 0)
        file_name = "test"+ str(test_case)+ ".json"
        folder = os.path.dirname(os.path.abspath(__file__)) + "/test"
        global graph
        graph = json.loads(open(os.path.join(folder, file_name), 'r').read())
        return Listing()
    def getReferenceManager(self):
        return ReferenceManager()
    def getFunctionManager(self):
        raise NotImplementedError("Please, for the love of god")

mock_peripheral_address = 0x40000000
class ReferenceManager():
    def getReferencesFrom(self, address):
        if str(address.getOffset()) in graph:
            return [Reference(address.getOffset())]
        elif address.getOffset() == mock_peripheral_address:
            return []
        else:
            return [Reference(mock_peripheral_address)]

class Listing():
    def getFunctionContaining(self, address):
        return Function(address)

    def getCodeUnitAt(self, address):
        pass

class Function():
    def __init__(self, address):
        self.address = address

    def getBody(self):
        return Body(self.address)

class Body():
    def __init__(self, address):
        self.address = address

    def getAddresses(self, address):
        return list(map(lambda x: Address(x),graph[str(self.address.getOffset())]))

class Reference():
    def __init__(self, target=0):
        self.target = target

    def toString(self):
        return str(self)

    def getToAddress(self):
        return Address(self.target)

    def getFromAddress(self):
        return Address(-999999999)

    def getReferenceType(self):
        return ReferenceType(self.target)
    
class ReferenceType():
    def __init__(self, target=0):
        self.target = target

    def isRead(self):
        return str(self.target) not in graph
    def isWrite(self):
        pass

    def isCall(self):
        return str(self.target) in graph

class Address():
    def __init__(self, target=0):
        self.target = target

    def toString(self):
        return str(self)

    def getOffset(self):
        return self.target

def getCurrentProgram():
    return Program()
