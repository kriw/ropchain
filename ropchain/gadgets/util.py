from ropchain import ropchain
def optMap(x, y, *args):
    if x != None:
        return x
    else:
        return y(*args)

optROPChain = lambda x: ropchain.ROPChain(x) if x != None else None

def toH8bitReg(reg):
    if reg == 'eax':
        return 'ah'
    elif reg == 'ebx':
        return 'bh'
    elif reg == 'ecx':
        return 'ch'
    elif reg == 'edx':
        return 'dh'

def toL8bitReg(reg):
    if reg == 'eax':
        return 'al'
    elif reg == 'ebx':
        return 'bl'
    elif reg == 'ecx':
        return 'cl'
    elif reg == 'edx':
        return 'dl'
