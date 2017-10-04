from ropchain import solver
from ropchain.gadgets import gadget

lib = './libc.so.6'
regs = {'eax': 0xb, 'ebx': 0x41414141, 'ecx': 0x0, 'edx': 0x0}
gadgets = gadget.load(lib)
rop = solver.solve(regs, gadgets)
rop.dump()
