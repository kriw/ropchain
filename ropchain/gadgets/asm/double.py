from ropchain.gadgets import util
from ropchain.gadgets.asm import add, shl, mov

def find(reg, gadgets, canUse):
    rop = add.find(reg, reg, gadgets, canUse)
    if rop != None:
        return rop

    rop = util.optMap(rop, fromOtherReg, reg, gadgets, canUse)
    rop = util.optMap(rop, fromShiftL, reg, gadgets, canUse)
    return None

def fromOtherReg(reg, gadgets, canUse):
    for r in canUse:
        _mov = mov.find(r, reg, gadgets, canUse - set(r))
        _add = add.find(reg, r, gadgets, canUse)
        if _mov != None and _add != None:
            return _mov + _add
    return None

def fromShiftL(reg, gadgets, canUse):
    return shl.find(reg, '0x1', gadgets, canUse)
