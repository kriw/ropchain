from gadgets import gadget, util
import ropchain


<<<<<<< HEAD
def mov(r1, r2, gadgets, canUse):
=======
def find(r1, r2, gadgets, canUse):
>>>>>>> 6dc821f... WIP refatoring for alternative gadgets
    rop = gadget.find(gadgets, 'mov', r1, r2)
    if rop != None:
        rop = ropchain.ROPChain(rop)
        return rop
<<<<<<< HEAD
    rop = util.optMap(rop, fromLea(r1, r2, gadgets))
    rop = util.optMap(rop, fromLeaWithOffset(r1, r2, gadgets))
    rop = util.optMap(rop, fromXorXor(r1, r2, gadgets))
    rop = util.optMap(rop, fromXorOr(r1, r2, gadgets))
    rop = util.optMap(rop, fromXchg(r1, r2, gadgets))
=======
    rop = util.optMap(rop, fromLea, r1, r2, gadgets, canUse)
    rop = util.optMap(rop, fromLeaWithOffset, r1, r2, gadgets, canUse)
    rop = util.optMap(rop, fromXorXor, r1, r2, gadgets, canUse)
    rop = util.optMap(rop, fromXorOr, r1, r2, gadgets, canUse)
    rop = util.optMap(rop, fromXchg, r1, r2, gadgets, canUse)
>>>>>>> 6dc821f... WIP refatoring for alternative gadgets
    return rop


'''
lea r1, [r2]
'''
<<<<<<< HEAD
def fromLea(r1, r2, gadgets):
    lea = gadget.find(gadgets, 'lea', r1, '[%s]' % r2)
    if lea != None:
        return ropchain.ROPChain(lea)
=======
def fromLea(r1, r2, gadgets, canUse):
    _lea = lea.find(r1, '[%s]' % r2, gadgets, canUse)
    if _lea != None:
        return ropchain.ROPChain(_lea)
>>>>>>> 6dc821f... WIP refatoring for alternative gadgets
    else:
        return None

'''
lea r1, [r2+n]
(dec r1) * n
'''
<<<<<<< HEAD
def fromLeaWithOffset(r1, r2, gadgets):
    lea, _, imm = gadget.findByRegex(gadgets, 'lea', r1, r'\[%s\+0x[0-9a-fA-F]*]')
    dec = gadget.find(gadgets, 'dec', r1)
    if lea != None and dec != None:
        return ropchain.ROPChain([lea] +  [dec] * imm)
=======
def fromLeaWithOffset(r1, r2, gadgets, canUse):
    #TODO replace find.ByRegex with wrapper function of lea
    _lea, _, imm = gadget.findByRegex(gadgets, 'lea', r1, r'\[%s\+0x[0-9a-fA-F]*]')
    _dec = dec.find(r1, gadgets, canUse)
    if _lea != None and _dec != None:
        return ropchain.ROPChain([_lea] +  [_dec] * imm)
>>>>>>> 6dc821f... WIP refatoring for alternative gadgets
    else:
        return None

'''
xor r1, r1;
xor r1, r2;
'''
<<<<<<< HEAD
def fromXorXor(r1, r2, gadgets):
    xorR1R1 = gadget.find(gadgets, 'xor', r1, r1)
    xorR1R2 = gadget.find(gadgets, 'xor', r1, r2)
=======
def fromXorXor(r1, r2, gadgets, canUse):
    xorR1R1 = xor.find(r1, r1, gadgets, canUse)
    xorR1R2 = xor.find(r1, r2, gadgets, canUse)
>>>>>>> 6dc821f... WIP refatoring for alternative gadgets
    if xorR1R1 != None and xorR1R2 != None:
        return ropchain.ROPChain([xorR1R1, xorR1R2])
    else:
        return None

'''
xor r1, r1
or r1, r2
'''
<<<<<<< HEAD
def fromXorOr(r1, r2, gadgets):
    xorR1R1 = gadget.find(gadgets, 'xor', r1, r1)
    orGadget = gadget.find(gadgets, 'or', r1, r2)
=======
def fromXorOr(r1, r2, gadgets, canUse):
    xorR1R1 = xor.find(r1, r1, gadgets, canUse)
    orGadget = orGadget.find(r1, r2, gadgets, canUse)
>>>>>>> 6dc821f... WIP refatoring for alternative gadgets
    if xorR1R1 != None and orGadget != None:
        return ropchain.ROPChain([xorR1R1, orGadget])
    else:
        return None

'''
xchg r1, r2
mov r2, r1
xchg r1, r2
'''
<<<<<<< HEAD
def fromXchg(r1, r2, gadgets):
    xchg = gadget.find(gadgets, 'xchg', r1, r2)
    mov = gadget.find(gadgets, 'mov', r2, r1)
    if xchg != None and mov != None:
        return ropchain.ROPChain([xchg, mov, xchg])
=======
def fromXchg(r1, r2, gadgets, canUse):
    _xchg = xchg.find(r1, r2, gadgets, canUse)
    _mov = mov.find(r2, r1, gadgets, canUse)
    if _xchg != None and _mov != None:
        return ropchain.ROPChain([_xchg, _mov, _xchg])
>>>>>>> 6dc821f... WIP refatoring for alternative gadgets
    else:
        return None


