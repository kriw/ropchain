from ropchain import frontend
from subprocess import call
import re
import os
import md5

def find(gadgets, mnem, op1=None, op2=None, op3=None):
    ops = list(filter(lambda x: x != None, [op1, op2, op3]))
    insn = Insn(mnem, ops)
    for gadget in gadgets:
        if gadget == insn:
            return gadget
    return None

def findByRegex(gadgets, mnem, op1=None, op2=None):
    for gadget in gadgets:
        for insn in gadget.insns:
            if not re.match(mnem, insn.mnem):
                continue
            if op1 != None and not re.match(op1, insn.ops[0]):
                continue
            if op2 != None and not re.match(op2, insn.ops[1]):
                continue
            return mnem, insn.ops[0], insn.ops[1]
    return None, None, None

class Insn:
    def __init__(self, mnem, ops):
        self.mnem = mnem
        self.ops = ops
    def __str__(self):
        return '%s %s' % (self.mnem, ', '.join(self.ops))
    def __eq__(a, b):
        if not a or not b:
            return False
        return a.mnem == b.mnem and a.ops == b.ops

class Gadget:
    def __init__(self, gadgets, addr=0):
        gadgets = list(filter(lambda x: len(x) > 0, gadgets))
        self.addr = addr
        self.insns = []
        for gadget in gadgets:
            ls = gadget.split()
            ls = list(map(lambda x: x.strip(), ls))
            mnem = ls[0]
            ops = list(map(lambda x: x.strip(), ' '.join(ls[1:]).split(",")))
            self.insns.append(Insn(mnem, ops))

    def toStr(self, base=0):
        return hex(self.addr + base) + " " + '; '.join(map(str, self.insns))

    def __eq__(self, _insn):
        if len(self.insns) == 0:
            return False
        return self.insns[0] == _insn

def readGadgets(filePath):
    return open(filePath).readlines()

def fromDict(gadgets):
    return [Gadget(insn.split(';'), addr) for addr, insn in gadgets.iteritems()]

#HACKME
def load(filePath):
    #check gadgetfile
    md5sum = ''.join(map(lambda x: "%02x" % ord(x), md5.new(open(filePath).read()).digest()))
    hashFullPath = "./.cache/ropchain/%s" % md5sum
    if not os.path.exists(hashFullPath):
        fullPathFrontEnd = os.path.dirname(os.path.abspath(frontend.__file__))
        call(["bash", "%s/ropgadget.sh" % fullPathFrontEnd, filePath])
    lines = readGadgets(hashFullPath)
    return parseGadget(lines)


def parseGadget(txtGadget):
    addrs = list(map(lambda x: int(x.replace(":", "").split()[0], 16), txtGadget))
    gadgets = list(map(lambda x: ' '.join(x.split()[1:]), txtGadget))
    gadgets = list(map(lambda x: list(map(lambda y: y.strip(),x.split(';'))), gadgets))
    gadgets, addrs = zip(*list(filter(lambda xs: any([x == 'ret' for x in xs[0]]), zip(gadgets, addrs))))
    return list(map(lambda x: Gadget(x[0], x[1]), zip(gadgets, addrs)))

