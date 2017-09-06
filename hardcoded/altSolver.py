import itertools
import gadget
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
        ans = min(ans, tmpAns) if tmpAns else ans

    for reg in ropChains:
        ans += ropChains[reg]
    return ans

def canCalc(dest, reg, gadgets):
    pop = gadget.find(gadgets, 'pop', reg)
    if pop != None:
        return ropchain.ROPChain(pop)

    inc = gadget.find(gadgets, 'inc', reg)
    add = gadget.find(gadgets, 'add', reg, reg)
    # print(reg, inc, add)
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
#

def toH8bitReg(reg):
    if reg == 'eax':
        return 'ah'
    elif reg == 'ebx':
        return 'bh'
    elif reg == 'ecx':
        return 'ch'
    elif reg == 'edx':
        return 'dh'

def toL8bitReg(reg):
    if reg == 'eax':
        return 'al'
    elif reg == 'ebx':
        return 'bl'
    elif reg == 'ecx':
        return 'cl'
    elif reg == 'edx':
        return 'dl'

def isImm(op):
    try:
        _ = int(op, 16)
        return True
    except ValueError:
        return False

#WIP
# | mov reg, other; ret; (add reg, reg; ret;)*; ([inc reg], add reg, reg)*; ret
'''
alt pop reg
| mov reg, imm; ret; (add reg, reg; ret;)*; ([inc reg], add reg, reg)*; ret
| mov reg, other; ret; (add reg, reg; ret;)*; ([inc reg], add reg, reg)*; ret
| xor reg, reg; ret; ([inc reg], add reg, reg)*; ret
| pop other; ret; mov reg, other; ret
| pop other; ret; xchg reg, other; ret
'''
def altPop(dest, reg, gadgets, canUse):
    if not reg in ['esi', 'edi']:
        movLimm, _, _ = gadget.findByRegex(gadgets, 'mov', '%s' % toL8bitReg(reg), r'0x[0-9a-fA-Z]*')
        addRegReg = gadget.find(gadgets, 'add', reg, reg)
        inc = gadget.find(gadgets, 'inc', reg)
        if movLimm != None and addRegReg != None and inc != None:
            while dest > 0:
                ret = ropchain.ROPChain([movLimm] + [addRegReg] * 32)
                if dest & 1 == 1:
                    ret.appendGadget(inc)
                dest >>= 1
                ret.appendGadget(addRegReg)
            return ret

    xor = gadget.find(gadgets, 'xor', reg, reg)
    inc = gadget.find(gadgets, 'inc', reg)
    addRegReg = gadget.find(gadgets, 'add', reg, reg)
    if xor == None and addRegReg != None:
        xor = [addRegReg] * 32

    # print(reg, xor, inc, addRegReg)
    if xor != None and inc != None and addRegReg != None:
        ret = ropchain.ROPChain(xor)
        while dest > 0:
            if dest & 1 == 1:
                ret.appendGadget(inc)
            dest >>= 1
            ret.appendGadget(addRegReg)
        return ret

    for r in canUse:
        pop = gadget.find(gadgets, 'pop', r)
        if pop == None:
            pop = altPop(dest, r, gadgets, canUse - set([r]))
        else:
            pop = ropchain.ROPChain(pop)
            pop.appendValue(dest)

        mov = gadget.find(gadgets, 'mov', reg, r)
        if mov == None:
            mov = altMov(reg, r, gadgets, canUse - set([reg, r]))

        if pop != None and mov != None:
            return ropchain.ROPChain([pop, mov])

        xchg = gadget.find(gadgets, 'xchg', reg, r)
        if pop != None and xchg != None:
            return ropchain.ROPChain([pop, xchg])

    return None

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
    lea = gadget.find(gadgets, 'lea', r1, '[%s]' % r2)
    if lea != None:
        return ropchain.ROPChain(lea)

    lea, _, imm = gadget.findByRegex(gadgets, 'lea', r1, r'\[%s\+0x[0-9a-fA-F]*]')
    dec = gadget.find(gadgets, 'dec', r1)
    if lea != None and dec != None:
        return ropchain.ROPChain([lea] +  [dec] * imm)

    xorR1R1 = gadget.find(gadgets, 'xor', r1, r1)
    xorR1R2 = gadget.find(gadgets, 'xor', r1, r2)
    if xorR1R1 != None and xorR1R2 != None:
        return ropchain.ROPChain([xorR1R1, xorR1R2])

    orGadget = gadget.find(gadgets, 'or', r1, r2)
    if xorR1R1 != None and orGadget != None:
        return ropchain.ROPChain([xorR1R1, orGadget])

    xchg = gadget.find(gadgets, 'xchg', r1, r2)
    mov = gadget.find(gadgets, 'mov', r2, r1)
    if xchg != None and mov != None:
        return ropchain.ROPChain([xchg, mov, xchg])

    return None

def altMul2(dest, reg, gadgets, cauUse):
    #find add reg, reg
    res = gadget.find(gadgets, 'add', reg, reg)
    if res != None:
        return ropchain.ROPChain(res)

    for r in cauUse:
        mov = gadget.find(gadgets, 'mov', r, reg)
        mov = mov if mov != None else altMov(r, reg, gadgets, cauUse - set(r))
        add = gadget.find(gadgets, 'add', reg, r)
        if mov != None and add != None:
            return ropchain.ROPChain([mov, add])
    return None

def altInc(reg, gadgets, canUse):
    neg = gadget.find(gadgets, 'neg', reg)
    dec = gadget.find(gadgets, 'dec', reg)
    if neg != None and dec != None:
        return ropchain.ROPChain([neg, dec, dec, neg])
    for r in canUse:
        lea = gadget.find(gadgets, 'lea', reg, '[%s+1]' % r)
        mov = gadget.find(gadgets, 'mov', r, reg)
        mov = mov if mov != None else altMov(r, reg, gadgets, canUse - set(r))
        if lea != None and mov != None:
            return ropchain.ROPChain([lea, mov])
    return None

def altXor(r1, r2, gadgets, cauUse):
    #mov reg[:8], imm; ret; (inc reg; ret)*; movzx reg, reg[:8]; ret
    movLimm, imm = gadget.findByRegex(gadgets, 'mov', '%s' % toL8bitReg(r1), r'0x[0-9a-fA-Z]*')
    inc = gadget.find(gadgets, 'inc', r1)
    movzx = gadget.find(gadgets, 'movzx', reg, toL8bitReg(reg))
    if movLimm != None and inc != None and movzx != None:
        return ropchain.ROPChain([movLimm] + [inc] * (0x100 - imm) + [movzx])

    orGadget = gadget.find(gadgets, 'or', '%s' % r1, '1')
    andGadget = gadget.find(gadgets, 'and', '%s' % r1, '1')
    dec = gadget.find(gadgets, 'dec %s' % r1)
    if orGadget != None and andGadget != None and dec != None:
        return ropchain.ROPChain([orGadget, andGadget, dec])
    return None

'''
* mov, xor, inc make a cycle

alt pop reg
| mov reg, imm; ret; (add reg, reg; ret;)*; ([inc reg], add reg, reg)*; ret
| mov reg, other; ret; (add reg, reg; ret;)*; ([inc reg], add reg, reg)*; ret
| xor reg, reg; ret; ([inc reg], add reg, reg)*; ret
| pop other; ret; mov reg, other; ret
| pop other; ret; xchg reg, other; ret

alt mov r1, r2
| lea r1, [r2]; ret
| lea r1, [r2+imm]; ret; (dec r1; ret)*
| xor r1, r1; ret; xor r1, r2; ret
| xor r1, r1; ret; add r1, r2; ret
| xor r1, r1; ret; or r1, r2; ret
| xchg r1, r2; ret mov r2, r1; ret; xchg r1, r2; ret

alt imul reg, 2
| add reg, reg
| mov r2, r1; ret; add r1, r2; ret

alt inc reg
| neg reg; ret; dec reg; ret dec reg; ret; neg reg; ret
| lea r2, [r1+1]; ret; mov r1, r2; ret

alt xor reg, reg
| mov reg[:8], imm; ret; (mov inc; ret)*; movzx reg, reg[:8]; ret
| or reg, 1; ret; and reg, 1; ret; dec reg; ret
'''
