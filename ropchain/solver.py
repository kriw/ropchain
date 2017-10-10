import ropchain
from gadgets import gadget, setVal, asm
from struct import pack
import itertools
import copy
import arch

def _solve(dests, gadgets, base, cond, proc):
    if arch.arch == arch.X86:
        regs = {'eax', 'ebx', 'ecx', 'edx', 'edi', 'esi', 'ebp'}
    elif arch.arch == arch.AMD64:
        regs = {'rax', 'rbx', 'rcx', 'rdx', 'rdi', 'rsi', 'rbp',
                'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'}
    ropChains = {reg: find(reg, dests[reg], gadgets, set(), cond, proc) for reg in dests}
    ropChains = dict((k, v) for k, v in ropChains.iteritems() if v)
    solvable = set(ropChains.keys())

    remains = set(dests.keys()) - solvable
    ans = None
    for rs in itertools.permutations(remains):
        tmpAns = ropchain.ROPChain([])
        canUse = copy.deepcopy(regs)
        for reg in rs:
            canUse.remove(reg)
            tmp = find(reg, dests[reg], gadgets, canUse, cond, proc)
            if tmp == None:
                tmpAns = None
                break
            tmpAns += tmp

        if ans == None:
            ans = tmpAns
        elif tmpAns != None and len(ans.payload()) > len(tmpAns.payload()):
            ans = tmpAns

    r = sum([ropChains[reg] for reg in ropChains], ans)
    r.setBase(base)
    return r

def solveWithFile(dests, fileName, base=0, avoids=[]):
    gadgets = gadget.load(fileName)
    return solveWithGadget(dests, gadgets, base, avoids)

def solveWithGadget(dests, gadgets, base=0, avoids=[]):
    # return _solve(dests, gadgets, base, lambda x: True, lambda a, b, c, d: None)
    return solveAvoidChars(dests, gadgets, base, avoids)

#TODO
def solveAvoidChars(dests, gadgets, base=0, avoids=[]):
    avoids = set(avoids)
    def cond(v):
        chars = set()
        for i in range(arch.bits() / 8):
            chars.add(v & 0xff)
            v >>= 8
        # print("avoids & chars: %s" % str(avoids & chars))
        return avoids & chars == set()

    def proc(reg, dest, gadgets, canUse):
        chars = set(range(0xff)) - avoids
        xorTable = [None] * 0x100
        for a in chars:
            for b in chars:
                xorTable[a^b] = (a, b)
        left, right = 0, 0
        for i in range(arch.bits() / 8):
            ab = xorTable[(dest >> (8*i)) & 0xff]
            if ab == None:
                filteredGadgets = copy.deepcopy(gadgets)
                for r in set(reg) | canUse:
                    filteredGadgets = list(filter(lambda g: g.eq('pop', r), filteredGadgets))
                return find(reg, dest, filteredGadgets, canUse, lambda x: True, lambda a, b, c, d: None)

            left = (left << 8) | a
            right = (right << 8) | b

        ropChainLeft = find(reg, left, gadgets, canUse, lambda x: True, lambda a, b, c, d: None)
        for r1 in canUse:
            xor = asm.xor.find(reg, r1, gadgets, canUse - set([reg, r1]))
            if xor != None:
                ropChainRight = find(r1, left, gadgets, canUse, lambda x: True, lambda a, b, c, d: None)
                return ropChainLeft + ropChainRight + xor

        return None

    gadgets = list(filter(lambda g: cond(g.addr + base), gadgets))
    return _solve(dests, gadgets, base, cond, proc)

def find(reg, dest, gadgets, canUse, cond, proc):
    if cond(dest):
        return setVal.find(reg, dest, gadgets, canUse)
    else:
        return proc(reg, dest, gadgets, canUse)