from unicorn import *
from unicorn.x86_const import *
from pwn import asm
import solve
from struct import unpack
import sys

lib = open('/lib/i386-linux-gnu/libc.so.6').read()
def align(n):
    ret = 0x0;
    while ret < n:
        ret += 0x1000
    return ret

# memory address where emulation starts
ADDRESS = 0x1000000
LIB_BASE = 0x7f000000
LIB_SIZE = align(len(lib))
STACK_BASE = 0xf7000000
STACK_SIZE = 200 * 1024 * 1024
DEST = 0x0
get_eax = lambda :mu.reg_read(UC_X86_REG_EAX)
get_ebx = lambda :mu.reg_read(UC_X86_REG_EBX)
get_ecx = lambda :mu.reg_read(UC_X86_REG_ECX)
get_edx = lambda :mu.reg_read(UC_X86_REG_EDX)

def init(payload):
    # initialize unicorn emulator
    mu = Uc(UC_ARCH_X86, UC_MODE_32)
    mu.mem_map(ADDRESS, 4 * 1024 * 1024)
    mu.mem_map(LIB_BASE, LIB_SIZE)
    mu.mem_map(STACK_BASE, STACK_SIZE)
    mu.mem_map(DEST, 0x1000)

    mu.reg_write(UC_X86_REG_ESP, STACK_BASE + STACK_SIZE / 2)
    mu.mem_write(ADDRESS, asm('ret'))
    mu.mem_write(LIB_BASE, lib)
    mu.mem_write(mu.reg_read(UC_X86_REG_ESP), payload)
    return mu

def execROPChain(payload):
    mu = init(payload)
    # emulate code in infinite time & unlimited instructions
    mu.emu_start(ADDRESS, DEST)

    r_eax = mu.reg_read(UC_X86_REG_EAX)
    r_ebx = mu.reg_read(UC_X86_REG_EBX)
    r_ecx = mu.reg_read(UC_X86_REG_ECX)
    r_edx = mu.reg_read(UC_X86_REG_EDX)
    r_ebp = mu.reg_read(UC_X86_REG_EBP)
    r_esp = mu.reg_read(UC_X86_REG_ESP)
    r_edi = mu.reg_read(UC_X86_REG_EDI)
    r_esi = mu.reg_read(UC_X86_REG_ESI)
    r_eip = mu.reg_read(UC_X86_REG_EIP)
    r_eflags = mu.reg_read(UC_X86_REG_EFLAGS)

    print("=========HALT==========")
    print(">>> EAX = 0x%x" % r_eax)
    print(">>> EBX = 0x%x" % r_ebx)
    print(">>> ECX = 0x%x" % r_ecx)
    print(">>> EDX = 0x%x" % r_edx)
    print(">>> EBP = 0x%x" % r_ebp)
    print(">>> ESP = 0x%x" % r_esp)
    print(">>> EDI = 0x%x" % r_edi)
    print(">>> ESI = 0x%x" % r_esi)
    print(">>> EIP = 0x%x" % r_eip)
    print(">>> EFLAGS = 0x%x" % r_eflags)


from solve import solve
from gadgets import gadget

def main(argv):
    # dests = {'eax': 0x41414242, 'ebx': 0x7fff1234}
    dests = {'eax': 0x41414242, 'esi': 0x7fff1234}
    # dests = {'esi': 0x7fff1234}
    # dests = {'eax': 0x41414242}
    gadgets = gadget.parseGadget(open(argv[1]).readlines())
    # gadgets = list(filter(lambda x: not 'pop' in x.mnems, gadgets))
    gadgets = list(filter(lambda x: not ('pop' in x.mnems and 'eax' in x.ops[0]), gadgets))
    res = solve(dests, gadgets, LIB_BASE)
    # res.dump()

    print('len(payload): %d' % len(res.payload()))
    execROPChain(res.payload())

if __name__ == '__main__':
    import sys
    main(sys.argv)

