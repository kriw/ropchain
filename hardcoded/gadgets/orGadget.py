from gadgets import util, gadget

def find(op1, op2, gadgets, canUse):
    rop = util.optROPChain(gadget.find(gadgets, 'or', op1, op2))
    return rop
