import ropchain
from gadgets import gadget, util, xor, add

def find(reg, gadgets, canUse):
    rop = fromXor(reg, gadgets, canUse)
    rop = util.optMap(rop, fromAddRegReg, reg, gadgets, canUse)
    rop = util.optMap(rop, fromOrAndDec, reg, reg, gadgets, canUse)
    return rop

def fromXor(reg, gadget, canUse):
    return xor.find(reg, reg, gadget, canUse)

def fromAddRegReg(reg, gadgets, canUse):
    return add.find(reg, reg, gadgets, canUse) * 32

#move to make 0 routine ?
'''
or reg 1; ret; and reg 1; dec
'''
def fromOrAndDec(reg, gadgets, canUse):
    _or = orGadget.find(reg, '0x1', gadgets, canUse)
    _and = andGadget.find(reg, '0x1', gadgets, canUse)
    _dec = dec.find(reg, gadgets, canUse)
    if _or != None and _and != None and _dec != None:
        return _or + _and + _dec
    return None
