from gadgets import util, gadget
import ropchain

def find(r1, r2, gadgets, canUse):
    xor = util.optROPChain(gadget.find(gadgets, 'xor', r1, r2))
    xor = util.optMap(xor, fromMovzx, r1, r2, gadgets, canUse)

    return xor

'''
mov reg[:8], imm; ret; (inc reg; ret)*; movzx reg, reg[:8]; ret
'''
#TODO replace gadget.find, gadget.findByRegex with wrapper of each instruction
def fromMovzx(r1, r2, gadgets, canUse):
    #FIXME
    return None

    movLimm, imm = gadget.findByRegex(gadgets, 'mov', '%s' % util.toL8bitReg(r1), r'0x[0-9a-fA-Z]*')
    inc = inc.find(r1, gadgets, canUse)
    movzx = gadget.find(gadgets, 'movzx', reg, toL8bitReg(reg))
    if movLimm != None and inc != None and movzx != None:
        return ropchain.ROPChain([movLimm] + inc * (0x100 - imm) + [movzx])
    else:
        return None

