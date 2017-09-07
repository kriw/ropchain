from gadgets import util, gadget
from gadgets.asm import inc
import ropchain

def find(r1, r2, gadgets, canUse):
    xor = util.optROPChain(gadget.find(gadgets, 'xor', r1, r2))

    return xor
