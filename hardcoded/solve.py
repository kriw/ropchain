import gadget
import ropchain

regs = set(['eax', 'ebx', 'ecx', 'edx', 'edi', 'esi'])

def getGadgetByMnem(mnem, gs):
    return list(filter(lambda xs: any([mnem in xs.mnems]), gs))

def getRegs(p, gs):
    rs = set()
    for reg in regs:
        for gadget in gs:
            if p(gadget, reg):
                rs.add(reg)
                break
    return rs

def isR1R2Mov(g):
    if g.mnems[0] != 'mov':
        return False
    return any([g.ops[0][0] == r1 and g.ops[0][1] == r2 for r1 in regs for r2 in regs])

def getLeaR2ToR1(r1, r2, gs):
    return list(filter(lambda x: x.mnems[0] == 'lea' and x.ops[0][0] == r1 and x.ops[0][1] == 'dword [%s]' % r2, gs))

def getMovR2ToR1(r1, r2, gs):
    return list(filter(lambda x: x.mnems[0] == 'mov' and x.ops[0][0] == r1 and x.ops[0][1] == r2, gs))

def getMovValToR(reg, gs):
    return list(filter(lambda x: x.mnems[0] == 'mov' and x.ops[0][0] == reg and '0x' == x.ops[0][1][:2], gs))

def getXchgR1R2(r1, r2, gs):
    return list(filter(lambda x: x.mnems[0] == 'xchg' and \
            ((x.ops[0][0] == r1 and x.ops[0][1] == r2) or (x.ops[0][0] == r2 and x.ops[0][1] == r1)) \
            , gs))

def getInc(r, gs):
    return list(filter(lambda x: x.mnems[0] == 'inc' and x.ops[0][0] == r, gs))

def getAddR1R1(r1, gs):
    return list(filter(lambda x: x.mnems[0] == 'add' and (x.ops[0][0] == r1 and x.ops[0][1] == r1), gs))

def altPop(reg, dest, gs):
    movs = getMovValToR(reg, gs)
    incs = getInc(reg, gs)
    adds = addR1R1(reg, gs)
    if len(movs) == 0:
        return None
    init = int(movs[0].ops[0][1], 16)
    ropChain = fromIncAdd(init, dest, incs[0], adds[0])
    return ropChain

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
    incRegs = {r: getInc(r, gadgets) for r in regs}
    addR1R1 = {r1: getAddR1R1(r1, gadgets) for r1 in regs}

    # for reg in regs:
    #     if len(incRegs[reg]) > 0 and len(addR1R1[reg]) > 0:
    #         ropChain = ropchain.fromIncAdd(0, 0x41414141, incRegs[reg][0], addR1R1[reg][0])
    ropChain = ropchain.constructROPChain(remainRegs, movs, leas, xchgs, pops, dests, base)
    ropChain.dump()
    return ropChain.payload()

def main(argv):
    # dests = {'eax': 0x41414242, 'ebx': 0x7fff1234}
    dests = {'eax': 0x41414242, 'esi': 0x7fff1234}
    # dests = {'eax': 0x41414242}
    # gadgets = gadget.parseGadget(open(argv[1]).readlines())
    gadgets = gadget.parseGadget(open(argv[1]).readlines())
    gadgets = list(filter(lambda x: not 'pop' in x.mnems, gadgets))
    import hoge
    # print(repr(hoge.hoge(dests, gadgets).payload()))
    print(hoge.hoge(dests, gadgets).dump())
    # payload = solve(dests, gadgets, 0)
    # print(repr(payload))

if __name__ == '__main__':
    import sys
    main(sys.argv)
