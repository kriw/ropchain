import ropchain
from gadgets import gadget, setVal
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
    ropChains = {reg: find(dests[reg], reg, gadgets, set(), cond, proc) for reg in dests}
    ropChains = dict((k, v) for k, v in ropChains.iteritems() if v)
    solvable = set(ropChains.keys())

    remains = set(dests.keys()) - solvable
    ans = None
    for rs in itertools.permutations(remains):
        tmpAns = ropchain.ROPChain([])
        canUse = copy.deepcopy(regs)
        for reg in rs:
            canUse.remove(reg)
            tmp = find(dests[reg], reg, gadgets, canUse, cond, proc)
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

def solveWithFile(dests, fileName, base=0):
    gadgets = gadget.load(fileName)
    return _solve(dests, gadgets, base, lambda x: True, lambda a, b, c, d: None)

def solveWithGadget(dests, gadgets, base=0):
    return _solve(dests, gadgets, base, lambda x: True, lambda a, b, c, d: None)

#TODO
def solveAvoidChars(dests, gadgets, avoids=[], base=0):
    avoids = set(avoids)
    def cond(v):
        chars = set()
        while v:
            chars.add(chr(v & 0xff))
            v >>= 8
        return avoids & chars == set()

    def proc(dest, reg, gadgets, canUse):
        chars = set(map(chr, range(0xff))) - avoids
        print "hoge"
    gadgets = list(filter(lambda g: cond(g.addr + base), gadgets))
    return find(dest, reg, gadgets, canUse, cond, proc)

def find(dest, reg, gadgets, canUse, cond, proc):
    if cond(dest):
        return setVal.find(reg, dest, gadgets, canUse)
    else:
        return proc(reg, dest, gadgets, canUse)
