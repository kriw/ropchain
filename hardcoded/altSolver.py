import itertools
from gadgets import gadget, pop, mov, dec, neg, xor, inc
import ropchain
import copy

def solveByAlt(dests, gadgets):
    regs = set(dests.keys())
    solvable = set()
    ropChains = {}
    for reg in regs:
        tmp = canCalc(dests[reg], reg, gadgets)
        if tmp != None:
            ropChains[reg] = tmp
            solvable.add(reg)

    remains = regs - solvable
    ans = ropchain.ROPChain([])
    for rs in itertools.permutations(remains):
        tmpAns = ropchain.ROPChain([])
        canUse = copy.deepcopy(regs)
        for reg in rs:
            canUse.remove(reg)
            tmp = altPop(dests[reg], reg, gadgets, canUse)
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

def canCalc(dest, reg, gadgets):
    pop = gadget.find(gadgets, 'pop', reg)
    if pop != None:
        ropChainPop = ropchain.ROPChain(pop)
        ropChainPop.appendValue(dest)
        return ropChainPop

    inc = gadget.find(gadgets, 'inc', reg)
    add = gadget.find(gadgets, 'add', reg, reg)
    #check inc reg, add reg, reg
    if inc != None and add != None:
        ret = ropchain.ROPChain([add] * 32)
        while dest > 0:
            if dest & 1 == 1:
                ret.appendGadget(inc)
            dest >>= 1
            ret.appendGadget(add)
        return ret

    return None

def isImm(op):
    try:
        _ = int(op, 16)
        return True
    except ValueError:
        return False


def altPop(dest, reg, gadgets, canUse):
    return pop.find(reg, dest, gadgets, canUse)

'''
alt mov r1, r2
| lea r1, [r2]; ret
| lea r1, [r2+imm]; ret; (dec r1; ret)*
| xor r1, r1; ret; xor r1, r2; ret
| xor r1, r1; ret; add r1, r2; ret
| xor r1, r1; ret; or r1, r2; ret
| xchg r1, r2; ret mov r2, r1; ret; xchg r1, r2; ret
'''
def altMov(r1, r2, gadgets, canUse):
    return mov.find(r1, r2, gadgets, canUse)

def altMul2(dest, reg, gadgets, cauUse):
    res = add.find(reg, reg, gadgets, canUse)
    if res != None:
        return ropchain.ROPChain(res)

    for r in cauUse:
        mov = mov.find(r, reg, gadgets, canUse - set(r))
        add = add.find(reg, r, gadgets, canUse)
        if mov != None and add != None:
            return ropchain.ROPChain([mov, add])
    return None

def altInc(reg, gadgets, canUse):
    return inc.find(reg, gadgets, canUse)

def altXor(r1, r2, gadgets, canUse):
    return xor.find(r1, r2, gadgets, canUse)
