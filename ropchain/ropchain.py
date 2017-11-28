from gadgets.gadget import Gadget
import struct
import arch

class ROPChain:
    def __init__(self, gadget, value=None, base=0):
        self.gadgets = []
        self.base = base

        if gadget is None:
            return

        if isinstance(gadget, ROPChain):
            self.chain(gadget)
        else:
            self.appendGadget(gadget, value)
            
    def isEmpty(self):
        return len(self.gadgets) == 0

    def appendGadget(self, gadget, value=None):
        self.gadgets.append(gadget)
        payload = ''
        if value is None:
            payload = 'A' * gadget.useStack
        else:
            payload = pack(value) + 'A' * (gadget.useStack - arch.word())

        if len(payload) > 0:
            self.gadgets.append(payload);

    def dump(self):
        for gadget in self.gadgets:
            if isinstance(gadget, Gadget):
                print gadget.toStr(self.base)
            else:
                print gadget

    def setBase(self, base):
        self.base = base

    def payload(self):
        payload = ''
        for gadget in self.gadgets:
            if isinstance(gadget, Gadget):
                payload += pack(gadget.addr + self.base)
            elif isinstance(gadget, basestring):
                payload += gadget
            else:
                print 'payload: something is wrong'
                # payload += pack(gadget.addr)
        return payload

    def chain(self, rop):
        self.gadgets += rop.gadgets

    def __iadd__(self, rop):
        self.chain(rop)
        return self

    def __add__(self, rop):
        self.gadgets += rop.gadgets
        return self

    def __radd__(self, rop):
        return self.__add__(rop)

    def __mul__(self, times):
        self.gadgets *= times
        return self

def pack(n):
    if arch.arch == arch.X86:
        return struct.pack("<I", n)
    elif arch.arch == arch.AMD64:
        return struct.pack("<Q", n)
