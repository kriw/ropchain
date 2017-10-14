from ropchain import frontend, arch
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

        self.changedRegs = findChangedRegs(self.insns[1:])

    def toStr(self, base=0):
        return hex(self.addr + base) + " " + '; '.join(map(str, self.insns))

    def __eq__(self, _insn):
        if len(self.insns) == 0:
            return False
        return self.insns[0] == _insn

def containIndirect(insn):
    return all([re.match('\[.+\]', s) != None for s in [insn.mnem] + insn.ops])

def findRegKind(reg):
    reg = reg.lower()
    convReg = lambda x: x if arch.arch == arch.AMD64 else 'e' + x[1:]
    if reg in ['rax', 'eax', 'ax', 'al', 'ah']:
        return convReg('rax')
    elif reg in ['rbx', 'ebx', 'bx', 'bl', 'bh']:
        return convReg('rbx')
    elif reg in ['rcx', 'ecx', 'cx', 'cl', 'ch']:
        return convReg('rcx')
    elif reg in ['rdx', 'edx', 'dx', 'dl', 'dh']:
        return convReg('rdx')
    elif reg in ['rdi', 'edi']:
        return convReg('rdi')
    elif reg in ['rsi', 'esi']:
        return convReg('rsi')
    elif reg in ['rbp', 'ebp']:
        return convReg('rbp')
    elif reg in ['r%d%s' % (i, s) for i in range(8, 16) for s in ['', 'd', 'w', 'b']]:
        if reg[-1] in ['d', 'w', 'b']:
            return reg[:-1]
        return reg
    else:
        return None

def findChangedRegs(insns):
    r1 = {findRegKind(insn.ops[0]) for insn in insns if len(insn.ops) > 0}
    r2 = {findRegKind(insn.ops[1]) for insn in insns if insn.mnem == 'xchg'}
    return r1 | r2

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

