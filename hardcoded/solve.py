import ropchain
from gadgets import gadget, pop, mov, dec, neg, xor, inc
import itertools
import copy

def solve(dests, gadgets):
    regs = set(dests.keys())
    ropChains = {reg: calcByOneReg(dests[reg], reg, gadgets) for reg in regs}
    ropChains = dict((k, v) for k, v in ropChains.iteritems() if v)
    solvable = set(ropChains.keys())

    remains = regs - solvable
    ans = None
    for rs in itertools.permutations(remains):
        tmpAns = ropchain.ROPChain([])
        canUse = copy.deepcopy(regs)
        for reg in rs:
            canUse.remove(reg)
            tmp = calcWithOtherRegs(dests[reg], reg, gadgets, canUse)
            if tmp == None:
                tmpAns = None
                break
            tmpAns += tmp

        if ans == None:
            ans = tmpAns
        elif tmpAns == None:
            ans = ans
        elif len(ans.payload()) > len(ans.payload()):
            ans = tmpAns

    return sum([ropChains[reg] for reg in ropChains], ans)

def calcByOneReg(dest, reg, gadgets):
    return pop.find(reg, dest, gadgets, set())

def calcWithOtherRegs(dest, reg, gadgets, canUse):
    return pop.find(reg, dest, gadgets, canUse)

def main(argv):
    # dests = {'eax': 0x41414242, 'ebx': 0x7fff1234}
    # dests = {'eax': 0x41414242, 'esi': 0x7fff1234}
    dests = {'esi': 0x7fff1234}
    # dests = {'eax': 0x41414242}
    gadgets = gadget.parseGadget(open(argv[1]).readlines())
    gadgets = list(filter(lambda x: not 'pop' in x.mnems, gadgets))
    # gadgets = list(filter(lambda x: not ('pop' in x.mnems and 'eax' in x.ops[0]), gadgets))
    res = solve(dests, gadgets)
    res.dump()

if __name__ == '__main__':
    import sys
    main(sys.argv)
