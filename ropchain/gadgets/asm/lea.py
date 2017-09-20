from ropchain.gadgets import util, gadget

def find(op1, op2, gadgets, canUse):
    rop = util.optROPChain(gadget.find(gadgets, 'lea', op1, op2))
    return rop
