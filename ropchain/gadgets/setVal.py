from ropchain.gadgets.asm import pop

def find(reg, dest, gadgets, canUse):
    return pop.find(reg, dest, gadgets, canUse)

