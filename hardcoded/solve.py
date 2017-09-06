import gadget
import ropchain

def main(argv):
    # dests = {'eax': 0x41414242, 'ebx': 0x7fff1234}
    dests = {'eax': 0x41414242, 'esi': 0x7fff1234}
    # dests = {'eax': 0x41414242}
    gadgets = gadget.parseGadget(open(argv[1]).readlines())
    gadgets = list(filter(lambda x: not 'pop' in x.mnems, gadgets))
    import altSolver
    res = altSolver.solveByAlt(dests, gadgets)
    res.dump()

if __name__ == '__main__':
    import sys
    main(sys.argv)
