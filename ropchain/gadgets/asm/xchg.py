from ropchain import ropchain
from ropchain.gadgets import util, gadget

def find(r1, r2, gadgets, canUse):
    rop = util.optROPChain(gadget.find(gadgets, 'xchg', r1, r2))
    rop = rop if rop != None else util.optROPChain(gadget.find(gadgets, 'xchg', r2, r1))
    return rop
