from ropchain.gadgets import util, gadget
from ropchain.gadgets.asm import inc
from ropchain import ropchain

def find(r1, r2, gadgets, canUse):
    xor = util.optROPChain(gadget.find(gadgets, 'xor', r1, r2))

    return xor
