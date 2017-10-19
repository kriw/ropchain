from ropchain import ropchain
from ropchain.gadgets import gadget, util

def find(reg, gadgets, canUse):
    neg, canUse = gadget.find(gadgets, canUse, 'neg', reg)
    return util.optROPChain(neg)
