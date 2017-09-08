import re
def find(gadgets, mnem, op1=None, op2=None, op3=None):
    for gadget in gadgets:
        ops = list(filter(lambda x: x != None, [op1, op2, op3]))
        if gadget.eq(mnem, ops):
            return gadget
    return None

def findByRegex(gadgets, mnem, op1=None, op2=None, op3=None):
    for gadget in gadgets:
        for i, _mnem in enumerate(gadget.mnems):
            if not re.match(mnem, _mnem):
                continue
            ops = gadget.ops[i]
            if op1 != None and not re.match(op1, ops[0]):
                continue
            if op2 != None and not re.match(op2, ops[1]):
                continue
            if op3 != None and not re.match(op3, ops[2]):
                continue
            return mnem, ops[0], ops[1], op[2]
    return None, None, None

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
        return hex(self.addr) + " " + '; '.join(map(lambda x: "%s %s" % (x[0], x[1]), zip(self.mnems, self.ops)))

    def puts(self):
        print(str(self))

    def eq(self, _mnem, _ops):
        return any([mnem == _mnem and ops == _ops for mnem, ops in zip(self.mnems, self.ops)])


def readGadgets(filePath):
    return open(filePath).readlines()

def parseGadget(txtGadget):
    addrs = list(map(lambda x: int(x.replace(":", "").split()[0], 16), txtGadget))
    gadgets = list(map(lambda x: ' '.join(x.split()[1:]), txtGadget))
    gadgets = list(map(lambda x: list(map(lambda y: y.strip(),x.split(';'))), gadgets))
    gadgets, addrs = zip(*list(filter(lambda xs: any([x == 'ret' for x in xs[0]]), zip(gadgets, addrs))))
    return list(map(lambda x: Gadget(x[0], x[1]), zip(gadgets, addrs)))

