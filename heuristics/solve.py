from struct import pack
regs = set(['eax', 'ebx', 'ecx', 'edx', 'edi', 'esi'])

class ROPChain:
    def __init__(self, gadgets):
        self.gadgets = gadgets

    def appendGadget(self, gadget):
        self.gadgets.append(gadget)

    def appendValue(self, value):
        gadget = Gadget([], value)
        self.gadgets.append(gadget)

    def dump(self):
        for g in self.gadgets:
            g.puts()

    def payload(self):
        return ''.join(map(lambda x: p32(x.addr), self.gadgets))

def p32(p):
    return pack("<I", p)

class Gadget:
    def __init__(self, gadgets, addr=0x41414141):
        self.addr = addr
        self.mnems = []
        self.ops = []
        for gadget in gadgets:
            ls = gadget.split(',')
            ls = sum([l.split() for l in ls], [])
            self.mnems.append(ls[0])
            self.ops.append(ls[1:])

    def __str__(self):
        return '; '.join(map(str, self.mnems)) + " " + '; '.join(map(str, self.ops))

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

def constructROPChain(remains, movs, pops, dests):
    ropChain = ROPChain([])
    for r1 in remains:
        for r2 in movs[r1]:
            if len(movs[r1][r2]) <= 0:
                continue
            ropChain.appendGadget(pops[r2])
            ropChain.appendValue(dests[r1])
            ropChain.appendGadget(movs[r1][r2][0])
            break

    for reg in dests:
        if reg in remains:
            continue
        ropChain.appendGadget(pops[reg])
        ropChain.appendValue(dests[reg])
    return ropChain

def getMovR2ToR1(r1, r2, gadgets):
    return list(filter(lambda x: x.ops[0][0] == r1 and x.ops[0][1] == r2, gadgets))

def parseGadget(txtGadget):
    gadgets = list(map(lambda x: list(map(lambda y: y.strip(),x.split(';'))), txtGadget))
    gadgets = list(filter(lambda xs: all([not '[' in x for x in xs]), gadgets))
    gadgets = list(filter(lambda xs: any([x == 'ret' for x in xs]), gadgets))
    return list(map(lambda x: Gadget(x), gadgets))

def solve(dests, gadgets):
    popRegs = getRegs(lambda x, y: x.mnems[0] == 'pop', gadgets)
    remainRegs = regs - popRegs
    movR1R2 = list(filter(lambda x: isR1R2Mov(x), gadgets))
    movR1R2 = list(filter(lambda x: x.ops[0][0] in remainRegs and not x.ops[0][1] in remainRegs, movR1R2))
    pops = {r1: list(filter(lambda x: x.ops[0][0] == r1, getGadgetByMnem('pop', gadgets)))[0] for r1 in popRegs}
    movs = {r1: {r2: getMovR2ToR1(r1, r2, movR1R2) for r2 in regs} for r1 in regs}

    ropChain = constructROPChain(remainRegs, movs, pops, dests)
    return ropChain.payload()

def main(argv):
    dests = {'eax': 10, 'ebx': 20}
    gadgets = parseGadget(open(argv[1]).readlines())
    payload = solve(dests, gadgets)
    print(payload)

if __name__ == '__main__':
    import sys
    main(sys.argv)
