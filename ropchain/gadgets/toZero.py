from ropchain import ropchain, arch
from ropchain.gadgets import gadget, util
from ropchain.gadgets.asm import xor, add, inc, dec, orGadget, andGadget, movzx

def find(reg, gadgets, canUse):
    rop = fromXor(reg, gadgets, canUse)
    rop = util.optMap(rop, fromMovInc, reg, gadgets, canUse)
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
    if _or is not None and _and is not None and _dec is not None:
        return _or + _and + _dec
    return None

'''
mov reg[:8], imm; ret; (inc reg; ret)*; movzx reg, reg[:8]; ret
'''
def fromMovzx(reg, gadgets, canUse):
    movLimm, imm, _, canUse = gadget.findByRegex(gadgets, canUse, 'mov', '%s' % util.toL8bitReg(reg), r'0x[0-9a-fA-Z]+')
    movLimm = util.optROPChain(movLimm)
    _inc = inc.find(reg, gadgets, canUse)
    _movzx = movzx.find(reg, util.toL8bitReg(reg), gadgets, canUse)
    if movLimm is not None and _inc is not None and _movzx is not None:
        return movLimm + _inc * (0x100 - imm) + _movzx
    else:
        return None

def fromMovInc(reg, gadgets, canUse):
    _mov, _, _, canUse = gadget.findByRegex(gadgets, canUse, 'mov', reg, r'0x%s' % ('F' * (arch.bits()/8)))
    _mov = util.optROPChain(_mov)
    _inc = inc.find(reg, gadgets, canUse)
    if _mov is not None and _inc is not None:
        return _mov + _inc
    return None

