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

## Features
* Fast (Implemented in C++)
* Alternative gadgets will be used  by heuristics in case required ROPGadgets (e.g., `pop rax; ret`) are not found.
* Able to exclude specific characters if needed.

## Requirement
* `C++17`
* `Boost.Python`
* `radare2`
* `rp++`

## Example

### Executable

```sh
ropchain -f /bin/ls -g r2 --rax=0x114514 -d
```

### Python

```python
>>> from ropchain import *
>>> ropchain.setArch(ropchain.Arch.AMD64)
>>> rop = solve({rax: 0x3b, rbx: 0x4242424242424242}, '/bin/ls', 0, {})
>>> rop.dump()
0x413072:        pop, rdi; ret
0x3b

0x40adf4:        mov, rax, rdi; ret

0x413700:        pop, rbx; ret
0x4242424242424242

>>> rop.payload()
'r0A\x00\x00\x00\x00\x00;\x00\x00\x00\x00\x00\x00\x00\xf4\xad@\x00\x00\x00\x00\x00\x007A\x00\x00\x00\x00\x00BBBBBBBB'
>>>
```

# Installation

You can install python module by pip.
```
pip install ropchain
```

For executable, you have to clone and build manually.
