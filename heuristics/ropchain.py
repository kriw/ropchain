from struct import pack
from gadget import Gadget

class ROPChain:
    def __init__(self, gadgets, base=0):
        self.gadgets = gadgets
        self.base = base

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

    def isGadget(self, gadget):
        return len(gadget.mnems) > 0

def constructROPChain(remains, movs, leas, xchgs, pops, dests, base):
    ropChain = ROPChain([], base)
    used = set()
    for r1 in remains:
        for r2 in xchgs:
            if len(xchgs[r1][r2]) <= 0 or r1 in used:
                continue
            ropChain.appendGadget(pops[r2])
            ropChain.appendValue(dests[r1])
            ropChain.appendGadget(xchgs[r1][r2][0])
            used.add(r1)
            break

    for r1 in remains:
        for r2 in leas:
            if len(leas[r1][r2]) <= 0 or r1 in used:
                continue
            ropChain.appendGadget(pops[r2])
            ropChain.appendValue(dests[r1])
            ropChain.appendGadget(leas[r1][r2][0])
            used.add(r1)
            break

    for r1 in remains:
        for r2 in movs:
            if len(movs[r1][r2]) <= 0 or r1 in used:
                continue
            ropChain.appendGadget(pops[r2])
            ropChain.appendValue(dests[r1])
            ropChain.appendGadget(movs[r1][r2][0])
            used.add(r1)
            break

    for reg in dests:
        if reg in remains:
            continue
        ropChain.appendGadget(pops[reg])
        ropChain.appendValue(dests[reg])
    return ropChain

def p32(p):
    return pack("<I", p)
