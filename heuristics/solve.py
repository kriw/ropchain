import gadget
import ropchain

regs = set(['eax', 'ebx', 'ecx', 'edx', 'edi', 'esi'])

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
def getLeaR2ToR1(r1, r2, gadgets):
    return list(filter(lambda x: x.mnems[0] == 'lea' and x.ops[0][0] == r1 and x.ops[0][1] == 'dword [%s]' % r2, gadgets))

def getMovR2ToR1(r1, r2, gadgets):
    return list(filter(lambda x: x.mnems[0] == 'mov' and x.ops[0][0] == r1 and x.ops[0][1] == r2, gadgets))

def getXchgR1R2(r1, r2, gadgets):
    return list(filter(lambda x: x.mnems[0] == 'xchg' and \
            ((x.ops[0][0] == r1 and x.ops[0][1] == r2) or (x.ops[0][0] == r2 and x.ops[0][1] == r1)) \
            , gadgets))

def getAddR1R1(r1, gadgets):
    return list(filter(lambda x: x.mnems[0] == 'add' and \
            (x.ops[0][0] == r1 and x.ops[0][1] == r1), gadget))

def solve(dests, gadgets, base):
    print("dests:")
    print(', '.join({"%s: %s" % (k, hex(dests[k])) for k in dests}))

    popRegs = getRegs(lambda x, y: x.mnems[0] == 'pop', gadgets)
    remainRegs = regs - popRegs
    remainRegs.add('ebx')
    movR1R2 = list(filter(lambda x: isR1R2Mov(x), gadgets))
    movR1R2 = list(filter(lambda x: x.ops[0][0] in remainRegs and not x.ops[0][1] in remainRegs, movR1R2))
    pops = {r1: list(filter(lambda x: x.ops[0][0] == r1, getGadgetByMnem('pop', gadgets)))[0] for r1 in popRegs}
    movs = {r1: {r2: getMovR2ToR1(r1, r2, gadgets) for r2 in regs} for r1 in regs}
    leas = {r1: {r2: getLeaR2ToR1(r1, r2, gadgets) for r2 in regs} for r1 in regs}
    xchgs = {r1: {r2: getXchgR1R2(r1, r2, gadgets) for r2 in regs} for r1 in regs}

    ropChain = ropchain.constructROPChain(remainRegs, movs, leas, xchgs, pops, dests, base)
    ropChain.dump()
    return ropChain.payload()

def main(argv):
    dests = {'eax': 0x41414242, 'ebx': 0x7fff1234}
    gadgets = gadget.parseGadget(open(argv[1]).readlines())
    payload = solve(dests, gadgets, 0)
    print(repr(payload))

if __name__ == '__main__':
    import sys
    main(sys.argv)
