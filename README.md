# ROPChain

Fast ROPChain generator for controlling the value of registers.  
This will find the gadgets by heuristics that the missing gadgets will be alternated by equivalent gadgets.

## Platform

### OS

| OS | status |
| :--: | :--: |
| Linux | tested |
| macOS | not tested |
| Windows | not tested |


### Architecture
x86, x64 architectures are supported.

## Feature
* Fast (Implemented in C++)
* Alternative gadgets will be used in case required ROPGadgets (e.g., `pop rax; ret`) are not found by heuristics.

## Requirement
Either `radare2` or `rp++` is needed for gathering ropgadgets.

## Usage
Both of executable and python libarary are available.

### Executable

```sh
ropchain -h
Usage ...
TODO
```

### Python Libarary
```python
import ropchain
#TODO
```

## Example

### Executable

```sh
ropchain -f /bin/ls -g r2 --rax=0x114514 -d
```

### Python

```python
import ropchain
#TODO
```

# Installation

```
pip install ropchain
```

# TODO
* Verify `useStack`, `changedRegs` by emulating gadgets.
* Automatically finding equivalent gadgets.
