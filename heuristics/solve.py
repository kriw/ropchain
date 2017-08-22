from struct import pack
regs = set(['eax', 'ebx', 'ecx', 'edx', 'edi', 'esi'])

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

def p32(p):
    return pack("<I", p)

class Gadget:
    def __init__(self, gadgets, addr=0):
        gadgets = list(filter(lambda x: len(x) > 0, gadgets))
        self.addr = addr
        self.mnems = []
        self.ops = []
        for gadget in gadgets:
            ls = gadget.split()
            ls = list(map(lambda x: x.strip(), ls))
            mnem = ls[0]
            ops = list(map(lambda x: x.strip(), ' '.join(ls[1:]).split(",")))
            self.mnems.append(mnem)
            self.ops.append(ops)

    def __str__(self):
        return '; '.join(map(lambda x: "%s %s" % (x[0], x[1]), zip(self.mnems, self.ops)))

    def puts(self):
        print(str(self))

def getGadgetByMnem(mnem, gadgets):
    return list(filter(lambda xs: any([mnem in xs.mnems]), gadgets))

def getRegs(p, gadgets):
    rs = set()
    for reg in regs:
        for gadget in gadgets:
            if p(gadget, reg):
                rs.add(reg)
                break
    return rs

def isR1R2Mov(gadget):
    if gadget.mnems[0] != 'mov':
        return False
    return any([gadget.ops[0][0] == r1 and gadget.ops[0][1] == r2 for r1 in regs for r2 in regs])

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

def getLeaR2ToR1(r1, r2, gadgets):
    return list(filter(lambda x: x.mnems[0] == 'lea' and x.ops[0][0] == r1 and x.ops[0][1] == 'dword [%s]' % r2, gadgets))

def getMovR2ToR1(r1, r2, gadgets):
    return list(filter(lambda x: x.mnems[0] == 'mov' and x.ops[0][0] == r1 and x.ops[0][1] == r2, gadgets))

def getXchgR1R2(r1, r2, gadgets):
    return list(filter(lambda x: x.mnems[0] == 'xchg' and \
            ((x.ops[0][0] == r1 and x.ops[0][1] == r2) or (x.ops[0][0] == r2 and x.ops[0][1] == r1)) \
            , gadgets))

def readGadgets(filePath):
    return open(filePath).readlines()

def parseGadget(txtGadget):
    addrs = list(map(lambda x: int(x.replace(":", "").split()[0], 16), txtGadget))
    gadgets = list(map(lambda x: ' '.join(x.split()[1:]), txtGadget))
    gadgets = list(map(lambda x: list(map(lambda y: y.strip(),x.split(';'))), gadgets))
    gadgets, addrs = zip(*list(filter(lambda xs: any([x == 'ret' for x in xs[0]]), zip(gadgets, addrs))))
    return list(map(lambda x: Gadget(x[0], x[1]), zip(gadgets, addrs)))

def solve(dests, gadgets, base):
    print("dests: %s" % str(dests))
    popRegs = getRegs(lambda x, y: x.mnems[0] == 'pop', gadgets)
    remainRegs = regs - popRegs
    remainRegs.add('ebx')
    movR1R2 = list(filter(lambda x: isR1R2Mov(x), gadgets))
    movR1R2 = list(filter(lambda x: x.ops[0][0] in remainRegs and not x.ops[0][1] in remainRegs, movR1R2))
    pops = {r1: list(filter(lambda x: x.ops[0][0] == r1, getGadgetByMnem('pop', gadgets)))[0] for r1 in popRegs}
    movs = {r1: {r2: getMovR2ToR1(r1, r2, gadgets) for r2 in regs} for r1 in regs}
    leas = {r1: {r2: getLeaR2ToR1(r1, r2, gadgets) for r2 in regs} for r1 in regs}
    xchgs = {r1: {r2: getXchgR1R2(r1, r2, gadgets) for r2 in regs} for r1 in regs}

    ropChain = constructROPChain(remainRegs, movs, leas, xchgs, pops, dests, base)
    ropChain.dump()
    return ropChain.payload()

def main(argv):
    dests = {'eax': 0x41414242, 'ebx': 0x7fff1234}
    gadgets = parseGadget(open(argv[1]).readlines())
    payload = solve(dests, gadgets, 0)
    print(repr(payload))

if __name__ == '__main__':
    import sys
    main(sys.argv)
