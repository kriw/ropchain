from ropchain.gadgets import gadget, util
from ropchain import ropchain

#TODO seprate add reg, reg; add reg, imm
def find(op1, op2, gadgets, canUse):
    rop, canUse = gadget.find(gadgets, canUse, 'add', op1, op2)
    return util.optROPChain(rop)

# def fromInc(op1, gadgets, canUse):
#     _inc = inc.find(op1, gadgets, canUse)
