from ropchain.gadgets.asm import pop
from ropchain.gadgets import toZero, util

def find(reg, dest, gadgets, canUse):
    rop = None
    if dest == 0:
        rop = toZero.find(reg, gadgets, canUse)
    rop = util.optMap(rop, pop.find, reg, dest, gadgets, canUse)
    return rop
