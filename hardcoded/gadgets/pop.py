import ropchain
<<<<<<< HEAD
from gadgets import gadget, util, mov
=======
from gadgets import gadget, util, mov, xor, inc, xchg, add, toZero
>>>>>>> 6dc821f... WIP refatoring for alternative gadgets
import ropchain

'''
alt pop reg
| mov reg, imm; ret; (add reg, reg; ret;)*; ([inc reg], add reg, reg)*; ret
| mov reg, other; ret; (add reg, reg; ret;)*; ([inc reg], add reg, reg)*; ret
| xor reg, reg; ret; ([inc reg], add reg, reg)*; ret
| pop other; ret; mov reg, other; ret
| pop other; ret; xchg reg, other; ret
'''

<<<<<<< HEAD
def pop(dest, reg, gadgets, canUse):
    rop = gadget.find(gadgets, dest, reg)
=======
def find(reg, dest, gadgets, canUse):
    rop = gadget.find(gadgets, 'pop', reg)
>>>>>>> 6dc821f... WIP refatoring for alternative gadgets
    if rop != None:
        rop =  ropchain.ROPChain(rop)
        rop.appendValue(dest)
        return rop
<<<<<<< HEAD
    rop = util.optMap(rop, popByIncAdd(dest, reg, gadgets))
    rop = util.optMap(rop, popByOtherReg(dest, reg, gadgets, canUse))
    rop = util.optMap(rop, popByCalc(dest, reg, gadgets))

    return rop

def popByIncAdd(dest, reg, gadgets):
    #TODO replace gadget.find with xor, inc searching routine
    xor = gadget.find(gadgets, 'xor', reg, reg)
    inc = gadget.find(gadgets, 'inc', reg)
    if inc == None:
        inc = altInc(acouhsa)
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
=======
    rop = util.optMap(rop, fromIncAdd, dest, reg, gadgets, canUse)
    rop = util.optMap(rop, fromOtherReg, dest, reg, gadgets, canUse)
    rop = util.optMap(rop, fromCalc, dest, reg, gadgets, canUse)

    return rop

'''
xor reg, reg; ret; ([inc reg], add reg, reg)*; ret
'''
def fromIncAdd(dest, reg, gadgets, canUse):
    #TODO replace gadget.find with xor, inc searching routine
    zero = toZero.find(reg, gadgets, canUse)
    _inc = inc.find(reg, gadgets, canUse)
    addRegReg = add.find(reg, reg, gadgets, canUse)

    # print(reg, xor, inc, addRegReg)
    if zero != None and _inc != None and addRegReg != None:
        ret = zero
        while dest > 0:
            if dest & 1 == 1:
                ret += _inc
            dest >>= 1
            ret += addRegReg
>>>>>>> 6dc821f... WIP refatoring for alternative gadgets
        return ret

    return None

<<<<<<< HEAD
def popByOtherReg(dest, reg, gadgets, canUse):
    for r in canUse:
        p = pop(dest, reg, gadgets, canUse - set([r]))
        m = mov.mov(reg, r, gadgets, canUse - set([reg, r]))

        if p != None and m != None:
            return ropchain.ROPChain([p, m])

        xchg = gadget.find(gadgets, 'xchg', reg, r)
        if p != None and xchg != None:
            return ropchain.ROPChain([p, xchg])

    return None

def popByCalc(dest, reg, gadgets):
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

    return None

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


=======
'''
pop other; ret; mov reg, other; ret
pop other; ret; xchg reg, other; ret
'''
def fromOtherReg(dest, reg, gadgets, canUse):
    for r in canUse:
        _pop = find(r, dest, gadgets, canUse - set([r]))
        _mov = mov.find(reg, r, gadgets, canUse - set([reg, r]))

        if _pop != None and _mov != None:
            return _pop + _mov

        _xchg = xchg.find(reg, r, gadgets, canUse - set(r))
        if _pop != None and _xchg != None:
            return _pop + _xchg

    return None

#FIXME
def fromCalc(dest, reg, gadgets, canUse):
    if not reg in ['esi', 'edi']:
        movLimm, _, _ = gadget.findByRegex(gadgets, 'mov', '%s' % util.toL8bitReg(reg), r'0x[0-9a-fA-Z]*')
        addRegReg = add.find(reg, reg, gadgets, canUse)
        _inc = inc.find(reg, gadgets, canUse)
        if movLimm != None and addRegReg != None and _inc != None:
            while dest > 0:
                ret = ropchain.ROPChain([movLimm] + addRegReg * 32)
                if dest & 1 == 1:
                    ret += _inc
                dest >>= 1
                ret += addRegReg
            return ret

    return None
>>>>>>> 6dc821f... WIP refatoring for alternative gadgets
