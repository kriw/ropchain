from ropchain import ropchain
from ropchain.gadgets import gadget, util

def find(reg, gadgets, canUse):
    dec, canUse = gadget.find(gadgets, canUse, 'dec', reg)
    return util.optROPChain(dec)

