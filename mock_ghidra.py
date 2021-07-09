import sys
import os

def getCurrentAddress():
    return Address()

class Program():
    def getListing(self):
        return Listing()
    def getReferenceManager(self):
        return ReferenceManager()
    def getFunctionManager(self):
        raise NotImplementedError("Please, for the love of god")


class ReferenceManager():
    def getReferencesFrom(self, address):
        if os.environ.get("TEST_CASE", 0):
            return self._generateBaseCase()
        else:
            return self._generateTriplet()

    def _generateBaseCase(self):
        print("generating base case")
        return []

    def _generateTriplet(self):
        print("generating triplet")
        return [Reference(0), Reference(0x4000000), Reference(1e9)]

class Listing():
    def getFunctionContaining(self, address):
        return Function()

class Function():
    def getBody(self):
        return Body()

class Body():
    def getAddresses(self, why):
        return [Address(), Address(), Address()]

class Reference():
    def __init__(self, target=0):
        self.target = target

    def toString(self):
        return str(self)

    def getToAddress(self):
        return Address(self.target)

    def getFromAddress(self):
        return Address(self.target)

    def getReferenceType(self):
        return ReferenceType()
    
class ReferenceType():
    def isRead(self):
        pass
    def isWrite(self):
        pass

    def isCall(self):
        pass


class Address():
    def __init__(self, target=0):
        self.target = target

    def toString(self):
        return str(self)

    def getOffset(self):
        return self.target

def getCurrentProgram():
    return Program()
