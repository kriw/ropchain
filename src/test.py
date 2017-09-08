from solve import solve
from gadgets import gadget
import emulator

def main():
    f = 'util/libcGadget.txt'
    # dests = {'eax': 0x41414242, 'ebx': 0x7fff1234}
    dests = {'eax': 0x41414242, 'esi': 0x7fff1234}
    # dests = {'esi': 0x7fff1234}
    # dests = {'eax': 0x41414242}
    gadgets = gadget.parseGadget(open(f).readlines())
    # gadgets = list(filter(lambda x: not 'pop' in x.mnems, gadgets))
    gadgets = list(filter(lambda x: not ('pop' in x.mnems and 'eax' in x.ops[0]), gadgets))
    res = solve(dests, gadgets, emulator.LIB_BASE)
    # res.dump()
    print('len(payload): %d' % len(res.payload()))
    emulator.execROPChain(res.payload())

if __name__ == '__main__':
    main()

