from ropchain import ropchain
from ropchain.gadgets import util, gadget

def find(r1, r2, gadgets, canUse):
    rop, canUse = gadget.find(gadgets, canUse, 'xchg', r1, r2)
    if rop == None:
        rop, canUse = gadget.find(gadgets, canUse, 'xchg', r2, r1)
        return util.optROPChain(rop)
    else:
        return ropchain.ROPChain(rop)
