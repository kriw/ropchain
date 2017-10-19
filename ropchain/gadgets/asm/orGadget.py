from ropchain.gadgets import util, gadget

def find(op1, op2, gadgets, canUse):
    rop, canUse = gadget.find(gadgets, canUse, 'or', op1, op2)
    return util.optROPChain(rop)
