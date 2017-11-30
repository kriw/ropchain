import ropchain
from gadgets import gadget, setVal, toZero, asm, util
import arch
from struct import pack
import itertools
import copy
import re


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
    isFail = True

    for rs in itertools.permutations(remains):
        tmpAns = ropchain.ROPChain(None)
        canUse = copy.deepcopy(regs)
        for reg in rs:
            canUse.remove(reg)
            tmp = find(reg, dests[reg], gadgets, canUse, cond, proc)
            if tmp is None:
                tmpAns = None
                break
            tmpAns = tmpAns + tmp if tmpAns else tmp

        if tmpAns is None:
            continue
        isFail = False
        ans = util.optMin(ans, tmpAns)

    if isFail:
        return None
    r = sum([ropChains[reg] for reg in ropChains], ans)
    r.setBase(base)
    return r

def solveWithFile(dests, fileName, base=0, avoids=[]):
    gadgets = gadget.load(fileName)
    return solveWithGadget(dests, gadgets, base, avoids)

def solveWithGadget(dests, gadgets, base=0, avoids=[]):
    return solveAvoidChars(dests, gadgets, base, avoids)

def solveAvoidChars(dests, gadgets, base=0, avoids=[]):
    avoids = set(avoids)
    def cond(v):
        chars = set()
        for i in range(arch.bits() / 8):
            chars.add(v & 0xff)
            v >>= 8
        return avoids & chars == set()

    def proc(reg, dest, gadgets, canUse):
        ans = None
        if dest == 0:
            rop = toZero.find(reg, gadgets, canUse)
            if rop is not None:
                ans = util.optMin(ans, rop)

        print reg, canUse
        #use xor r1, r2
        chars = set(range(0xff)) - avoids
        xorTable = [None] * 0x100
        canConstruct = True
        for a in chars:
            for b in chars:
                xorTable[a^b] = (a, b)
        left, right = 0, 0
        for i in range(arch.bits() / 8):
            ab = xorTable[(dest >> (8*i)) & 0xff]
            if ab is None:
                canConstruct = False
                break
            left = left | ab[0] << (i * 8)
            right = right | ab[1] << (i * 8)

        if canConstruct:
            ropChainLeft = find(reg, left, gadgets, canUse, lambda x: True, lambda a, b, c, d: None)
            for r1 in canUse:
                xor = asm.xor.find(reg, r1, gadgets, canUse - set([reg, r1]))
                if xor != None:
                    ropChainRight = find(r1, right, gadgets, canUse, lambda x: True, lambda a, b, c, d: None)
                    ans = util.optMin(ans, ropChainLeft + ropChainRight + xor)

        #use reg <- somevalue; ret; (inc reg)*(value-someValue)
        tmpDest = 0
        canConstruct = True
        for i in range(arch.word()):
            byte = (dest >> (arch.bits() - 8*(i+1))) & 0xff
            filtered = filter(lambda x: x <= byte, chars)
            if len(filtered) > 0 and max(filtered) == byte:
                tmpDest = (tmpDest << 8) + byte
            elif len(filtered) > 0:
                a = max(chars)
                tmpDest = (tmpDest << (arch.bits() - 8*i)) + \
                        int((arch.word()-i)*("%x"%(a)), 16)
                break
            else:
                tmpDest -= 1
                p = lambda x: all([chr((x>>j)&0xff) for j in range(i)])
                while not p(tmpDest) and tmpDest > 0:
                    tmpDest -= 1
                if tmpDest <= 0:
                    canConstruct = False
                else:
                    a = max(chars)
                    tmpDest = (tmpDest << (arch.bits() - 8*i)) + \
                            int((arch.word()-i)*("%x"%(a)), 16)
                break

        if canConstruct:
            print hex(dest), hex(tmpDest)
            _pop = setVal.find(reg, tmpDest, gadgets, canUse)
            _inc = asm.inc.find(reg, gadgets, canUse)
            if _pop is not None and _inc is not None:
                ans = util.optMin(ans, _pop + _inc * (dest - tmpDest))

        #use reg <- 0; ret; (inc reg)*value
        zero = setVal.find(reg, 0, gadgets, canUse)
        _inc = asm.inc.find(reg, gadgets, canUse)
        if dest < 0x1000 and zero is not None and _inc is not None:
            ans = util.optMin(ans, zero + _inc * dest)

        return ans

    gadgets = list(filter(lambda g: cond(g.addr + base), gadgets))
    def uniq(xs):
        ret = [xs[0]]
        for x in xs[1:]:
            if x != ret[-1]:
                ret.append(x)
        return ret
    gadgets = sorted(gadgets, key=lambda x: len(x.changedRegs))
    gadgets = uniq(gadgets)
    # for g in gadgets:
    #     print g.toStr()

    return _solve(dests, gadgets, base, cond, proc)

def find(reg, dest, gadgets, canUse, cond, proc):
    if cond(dest):
        return setVal.find(reg, dest, gadgets, canUse)
    else:
        return proc(reg, dest, gadgets, canUse)
