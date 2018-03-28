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
* `radare2` (Optional)
* `rp++`

## Usage
### Executable

```sh
Usage: ropchain -f <filename> --[reg]=<value>
-a: Architecture, "x86" or "amd64"
-b: Base address of binary file
-d: Dump mode
-f: Filename
-g: ROPGadget loader, "r2" or "rpp"
-i: Characters which should be excluded (e.g., -iabc
--[reg]: Register value (e.g. --rax=0x1234 --rbx=11
```

## Example
### Executable

```sh
ropchain -f /bin/ls -g r2 --rax=0x114514 -d -a amd64
```
### Python
[Examples](./examples) are available.
```python
>>> from ropchain import *
>>> libropchain.setArch(libropchain.Arch.AMD64)
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
