#!/usr/bin/python2
import ropchain
ropchain.setLoader(ropchain.Loader.R2)
fileName = "/bin/ls"
base = 0
dests = ropchain.RegValue()
dests[ropchain.Regs.rdi] = 1
avoids = ropchain.CharVec()
avoids.append('a')

rop = ropchain.solve(dests, fileName, base, avoids)
rop.dump()
