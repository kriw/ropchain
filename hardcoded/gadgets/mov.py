from gadgets import gadget, util
import ropchain


def find(r1, r2, gadgets, canUse):
    rop = gadget.find(gadgets, 'mov', r1, r2)
    if rop != None:
        rop = ropchain.ROPChain(rop)
        return rop
    rop = util.optMap(rop, fromLea, r1, r2, gadgets, canUse)
    rop = util.optMap(rop, fromLeaWithOffset, r1, r2, gadgets, canUse)
    rop = util.optMap(rop, fromXorXor, r1, r2, gadgets, canUse)
    rop = util.optMap(rop, fromXorOr, r1, r2, gadgets, canUse)
    rop = util.optMap(rop, fromXchg, r1, r2, gadgets, canUse)
    return rop


'''
lea r1, [r2]
'''
def fromLea(r1, r2, gadgets, canUse):
    _lea = lea.find(r1, '[%s]' % r2, gadgets, canUse)
    if _lea != None:
        return ropchain.ROPChain(_lea)
    else:
        return None

'''
lea r1, [r2+n]
(dec r1) * n
'''
def fromLeaWithOffset(r1, r2, gadgets, canUse):
    #TODO replace find.ByRegex with wrapper function of lea
    _lea, _, imm = gadget.findByRegex(gadgets, 'lea', r1, r'\[%s\+0x[0-9a-fA-F]*]')
    _dec = dec.find(r1, gadgets, canUse)
    if _lea != None and _dec != None:
        return ropchain.ROPChain([_lea] +  [_dec] * imm)
    else:
        return None

'''
xor r1, r1;
xor r1, r2;
'''
def fromXorXor(r1, r2, gadgets, canUse):
    xorR1R1 = xor.find(r1, r1, gadgets, canUse)
    xorR1R2 = xor.find(r1, r2, gadgets, canUse)
    if xorR1R1 != None and xorR1R2 != None:
        return ropchain.ROPChain([xorR1R1, xorR1R2])
    else:
        return None

'''
xor r1, r1
or r1, r2
'''
def fromXorOr(r1, r2, gadgets, canUse):
    xorR1R1 = xor.find(r1, r1, gadgets, canUse)
    orGadget = orGadget.find(r1, r2, gadgets, canUse)
    if xorR1R1 != None and orGadget != None:
        return ropchain.ROPChain([xorR1R1, orGadget])
    else:
        return None

'''
xchg r1, r2
mov r2, r1
xchg r1, r2
'''
def fromXchg(r1, r2, gadgets, canUse):
    _xchg = xchg.find(r1, r2, gadgets, canUse)
    _mov = mov.find(r2, r1, gadgets, canUse)
    if _xchg != None and _mov != None:
        return ropchain.ROPChain([_xchg, _mov, _xchg])
    else:
        return None


