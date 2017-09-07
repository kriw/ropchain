from gadgets import gadget
import altSolver
import ropchain

def main(argv):
    # dests = {'eax': 0x41414242, 'ebx': 0x7fff1234}
    # dests = {'eax': 0x41414242, 'esi': 0x7fff1234}
    dests = {'esi': 0x7fff1234}
    # dests = {'eax': 0x41414242}
    gadgets = gadget.parseGadget(open(argv[1]).readlines())
    gadgets = list(filter(lambda x: not 'pop' in x.mnems, gadgets))
    # gadgets = list(filter(lambda x: not ('pop' in x.mnems and 'eax' in x.ops[0]), gadgets))
    res = altSolver.solveByAlt(dests, gadgets)
    res.dump()

if __name__ == '__main__':
    import sys
    main(sys.argv)
