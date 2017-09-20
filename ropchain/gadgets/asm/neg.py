from ropchain import ropchain
from ropchain.gadgets import gadget 

def find(reg, gadgets, canUse):
    neg = gadget.find(gadgets, 'neg', reg)
    if neg != None:
        return ropchain.ROPChain(neg)
    else:
        return None

