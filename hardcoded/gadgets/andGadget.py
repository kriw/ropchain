from gadgets import util

def find(op1, op2, gadgets, canUse):
    rop = util.optROPChain(gadget.find(gadgets, 'and', op1, op2))
    return rop

