from ropchain import ropchain
from ropchain.gadgets import gadget, util
from ropchain.gadgets.asm import xor, add, inc, dec, orGadget, andGadget, movzx

def find(reg, gadgets, canUse):
    rop = fromXor(reg, gadgets, canUse)
    rop = util.optMap(rop, fromAddRegReg, reg, gadgets, canUse)
    rop = util.optMap(rop, fromOrAndDec, reg, gadgets, canUse)
    rop = util.optMap(rop, fromMovzx, reg, gadgets, canUse)
    return rop

def fromXor(reg, gadget, canUse):
    return xor.find(reg, reg, gadget, canUse)

def fromAddRegReg(reg, gadgets, canUse):
    addRegReg =  add.find(reg, reg, gadgets, canUse)
    if addRegReg != None:
        return addRegReg * 32
    else:
        return None

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

'''
mov reg[:8], imm; ret; (inc reg; ret)*; movzx reg, reg[:8]; ret
'''
def fromMovzx(reg, gadgets, canUse):
    movLimm, imm, _ = gadget.findByRegex(gadgets, 'mov', '%s' % util.toL8bitReg(reg), r'0x[0-9a-fA-Z]+')
    _inc = inc.find(reg, gadgets, canUse)
    _movzx = movzx.find(reg, util.toL8bitReg(reg), gadgets, canUse)
    if movLimm != None and _inc != None and _movzx != None:
        return ropchain.ROPChain([movLimm] + _inc * (0x100 - imm) + _movzx)
    else:
        return None

