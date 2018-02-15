This project is a work in progress.
# ROPChain

[![Build Status](https://api.travis-ci.org/kriw/ropchain.svg?branch=master)](https://travis-ci.org/kriw/ropchain)

Fast ROPChain generator for controlling the value of registers.  
This will find the gadgets by heuristics that the missing gadgets will be alternated by equivalent gadgets.

## Platform

### OS

| OS | status |
| :--: | :--: |
| Linux | tested |
| macOS | TODO |
| Windows | TODO |


### Architecture
x86, x64 architectures are supported.

## Feature
* Fast (Implemented in C++)
* Alternative gadgets will be used  by heuristics in case required ROPGadgets (e.g., `pop rax; ret`) are not found.
* Able to exclude specific characters if needed.

## Requirement
* `radare2`
* `rp++`

## Example

### Executable

```sh
ropchain -f /bin/ls -g r2 --rax=0x114514 -d
```

### Python

```python
#!/usr/bin/python2
import ropchain

fileName = "/bin/ls"
base = 0
dests = ropchain.RegValue()
dests[ropchain.Regs.rdi] = 1
avoids = ropchain.CharVec()
avoids.append('a')

rop = ropchain.solve(dests, fileName, base, avoids)
rop.dump()
print rop.payload()
```

# Installation

```
pip install ropchain
```

# TODO
* Verify `useStack`, `changedRegs` by emulating gadgets.
* Automatically finding equivalent gadgets.
