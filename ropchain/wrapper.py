import ropchain
from register import *

def toCharVec(s):
    ret = ropchain.CharVec()
    for c in s:
        ret.append(c)
    return ret

def solve(dests, fileName, base, _avoids):
    avoids = toCharVec(_avoids)
    return ropchain.solve(dests, fileName, base, avoids)

def solveFromDict(dests, gadgetDict, base, _avoids):
    avoids = toCharVec(_avoids)
    return ropchain.solveWithMap(dests, gadgetDict, base, avoids)
