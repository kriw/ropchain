from struct import pack
from gadgets.gadget import Gadget

class ROPChain:
    def __init__(self, gadgets, base=0):
        self.gadgets = []
        self.base = base

        if not isinstance(gadgets, list):
            gadgets = [gadgets]

        for gadget in gadgets:
            if gadget == None:
                continue

            if isinstance(gadget, ROPChain):
                self.chain(gadget)
            else:
                self.gadgets.append(gadget)

    def appendGadget(self, gadget):
        self.gadgets.append(gadget)

    def appendValue(self, value):
        gadget = Gadget([], value)
        self.gadgets.append(gadget)

    def dump(self):
        for g in self.gadgets:
            g.puts()

    def setBase(base):
        self.base = base

    def payload(self):
        payload = ''
        for gadget in self.gadgets:
            if self.isGadget(gadget):
                payload += p32(gadget.addr + self.base)
            else:
                payload += p32(gadget.addr)
        return payload

    def chain(self, ropChain):
        self.gadgets += ropChain.gadgets

    def isGadget(self, gadget):
        return len(gadget.mnems) > 0

    def __iadd__(self, ropChain):
        self.chain(ropChain)
        return self

    def __add__(self, ropChain):
        self.gadgets += ropChain.gadgets
        return self

    def __radd__(self, ropChain):
        return self.__add__(ropChain)

    def __mul__(self, times):
        self.gadgets *= times
        return self

def p32(p):
    return pack("<I", p)
