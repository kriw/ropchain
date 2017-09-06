import ropchain

def find(reg, gadgets, canUse):
    dec = gadget.find(gadgets, 'dec', reg)
    if dec != None:
        return ropchain.ROPChain(dec)
    else:
        return None

