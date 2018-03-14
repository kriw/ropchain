import libropchain
from register import *

def toCharVec(s):
    ret = libropchain.CharVec()
    for c in s:
        ret.append(c)
    return ret

def toRegValue(dest):
    ret = libropchain.RegValue()
    for k in dest:
        ret[k] = dest[k]
    return ret

def toInsnStr(gadgetDict):
    ret = libropchain.InsnStr()
    for k in gadgetDict:
        ret[k] = gadgetDict[k]
    return ret

def solve(_dests, fileName, base, _avoids):
    avoids = toCharVec(_avoids)
    dests = toRegValue(_dests)
    return libropchain.solve(dests, fileName, base, avoids)

#For Debug
def solveFromDict(_dests, _gadgetDict, base, _avoids):
    avoids = toCharVec(_avoids)
    dests = toRegValue(_dests)
    gadgetDict = toInsnStr(_gadgetDict)
    return libropchain.solveWithMap(dests, gadgetDict, base, avoids)
