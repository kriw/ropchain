regs = ['eax', 'ebx', 'ecx', 'edx', 'edi', 'esi']

class Gadget:
    def __init__(self, gadget):
        ls = gadget.split(',')
        ls = sum([l.split() for l in ls], [])
        self.mnem = ls[0]
        self.ops = ls[1:]

    def __str__(self):
        return str(self.mnem) + " " + str(self.ops)

def getGadgetByMnem(mnem, gadgets):
    return list(filter(lambda xs: any([mnem == x.mnem for x in xs]), gadgets))

def printGadgets(gadgets):
    for g in gadgets:
        print(' '.join(map(str, g)))

def isAddRegReg(gadget, reg):
    return gadget.mnem == 'add' and reg == gadget.ops[0] and reg == gadget.ops[1]

def isXorRegReg(gadget, reg):
    return gadget.mnem == 'xor' and reg == gadget.ops[0] and reg == gadget.ops[1]

def getRegs(p, gadgets):
    rs = set()
    for reg in regs:
        for gadget in gadgets:
            if any([p(g, reg) for g in gadget]):
                rs.add(reg)
                break
    return rs

def main(argv):
    gadgets = list(map(lambda x: list(map(lambda y: y.strip(),x.split(';'))), open(argv[1]).readlines()))
    gadgets = list(filter(lambda xs: all([not '[' in x for x in xs]), gadgets))
    gadgets = list(filter(lambda xs: any([x == 'ret' for x in xs]), gadgets))
    gadgets = list(map(lambda x: list(map(lambda y: Gadget(y), x)), gadgets))
    # printGadgets(gadgets)

    incGadget = getGadgetByMnem('inc', gadgets)
    addGadget = getGadgetByMnem('add', gadgets)
    xorGadget = getGadgetByMnem('xor', gadgets)
    movGadget = getGadgetByMnem('mov', gadgets)
    xchgGadget = getGadgetByMnem('xchg', gadgets)
    printGadgets(movGadget)
    printGadgets(xchgGadget)

    addAddRegs = getRegs(isAddRegReg, gadgets)
    incRegs = getRegs(lambda x, y: x.mnem == 'inc', gadgets)
    popRegs = getRegs(lambda x, y: x.mnem == 'pop', gadgets)
    xorRegs = getRegs(isXorRegReg, gadgets)

    calcRegs = addAddRegs & incRegs
    print('add reg, reg', addAddRegs)
    print('inc reg', incRegs)
    print('pop reg', popRegs)
    print('xor reg, reg', xorRegs)
    print('calc Regs', calcRegs)



if __name__ == '__main__':
    import sys
    main(sys.argv)
