import itertools
from gadgets import gadget, pop, mov, dec, neg, xor, inc
import ropchain
import copy

def solveByAlt(dests, gadgets):
    regs = set(dests.keys())
    ropChains = {reg: calcByOneReg(dests[reg], reg, gadgets) for reg in regs}
    ropChains = dict((k, v) for k, v in ropChains.iteritems() if v)
    solvable = set(ropChains.keys())

    remains = regs - solvable
    ans = ropchain.ROPChain([])
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
        if len(ans.payload()) == 0:
            ans = tmpAns
        elif len(ans.payload()) > len(ans.payload()):
            ans = tmpAns

    for reg in ropChains:
        ans += ropChains[reg]
    return ans

def calcByOneReg(dest, reg, gadgets):
    return pop.find(reg, dest, gadgets, set())

def calcWithOtherRegs(dest, reg, gadgets, canUse):
    return pop.find(reg, dest, gadgets, canUse)
