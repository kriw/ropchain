import ropchain
from gadgets.asm import mov, xor, inc, xchg, add, double
from gadgets import util, gadget, toZero
import ropchain

'''
alt pop reg
| mov reg, imm; ret; (add reg, reg; ret;)*; ([inc reg], add reg, reg)*; ret
| mov reg, other; ret; (add reg, reg; ret;)*; ([inc reg], add reg, reg)*; ret
| xor reg, reg; ret; ([inc reg], add reg, reg)*; ret
| pop other; ret; mov reg, other; ret
| pop other; ret; xchg reg, other; ret
'''

def find(reg, dest, gadgets, canUse):
    rop = gadget.find(gadgets, 'pop', reg)
    if rop != None:
        rop =  ropchain.ROPChain(rop)
        rop.appendValue(dest)
        return rop

    rop = util.optMap(rop, fromIncAdd, dest, reg, gadgets, canUse)
    rop = util.optMap(rop, fromOtherReg, dest, reg, gadgets, canUse)
    rop = util.optMap(rop, fromCalc, dest, reg, gadgets, canUse)

    return rop

'''
xor reg, reg; ret; ([inc reg], add reg, reg)*; ret
'''
def fromIncAdd(dest, reg, gadgets, canUse):
    zero = toZero.find(reg, gadgets, canUse)
    _inc = inc.find(reg, gadgets, canUse)
    _double = double.find(reg, gadgets, canUse)

    if zero != None and _inc != None and _double != None:
        ret = zero
        while dest > 0:
            if dest & 1 == 1:
                ret += _inc
            dest >>= 1
            ret += _double
        return ret

    return None

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
