import ropchain
from gadgets import gadget, setVal
import itertools
import copy

def solve(dests, gadgets, base=0):
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

    r = sum([ropChains[reg] for reg in ropChains], ans)
    r.setBase(base)
    return r

def calcByOneReg(dest, reg, gadgets):
    return setVal.find(reg, dest, gadgets, set())

def calcWithOtherRegs(dest, reg, gadgets, canUse):
    return setVal.find(reg, dest, gadgets, canUse)
