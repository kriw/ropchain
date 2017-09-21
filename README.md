# ROPChain

This repository is work in progress.  

Automatic ROPChain generator for controlling the value of registers.  

The x86 archtecture is supported. (Not yet x64, others)  

You can construct ROPChain like following.  
```python
from ropchain import solver
from ropchain.gadgets import gadget

base = 0xf7000000
binsh = base + 0x15b9ab
regs = {'eax': 0xb, 'ebx': binsh, 'ecx': 0x0, 'edx': 0x0}
print("libc base: %s" % hex(base))
gadgets = gadget.parseGadget(open('./gadgetList.txt').readlines())
rop = solver.solve(regs, gadgets, base)
rop.dump()

# Here is the result of rop.dump().
# 0xf757d06e pop eax; ret
# 0xb
# 0xf755aaa6 pop edx; ret
# 0x0
# 0xf7571395 pop ebx; ret
# 0xf76b49ab
# 0xf760e377 pop ecx; ret
# 0x0
```

## Feature
Using alternative gadgets in case pop gadgets cannot be used.

# Installation

```
pip install ropchain
```

# TODO

* Instruction for how to install.
* Fix bugs.
* Support for x64, other archtectures.
* Generation ROPChain without newline('\n') and space(' ') characters
* Generating ascii printable ROPChain.
* Rewriting to C++.
* Automatically finding equivalent gadgets.
