from ropchain.gadgets import gadget, util
from ropchain import ropchain

#TODO seprate add reg, reg; add reg, imm
def find(op1, op2, gadgets, canUse):
    rop = util.optROPChain(gadget.find(gadgets, 'add', op1, op2))
    return rop

# def fromInc(op1, gadgets, canUse):
#     _inc = inc.find(op1, gadgets, canUse)
