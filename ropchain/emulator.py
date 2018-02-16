from unicorn import *
from unicorn.x86_const import *
from register import *
from pwn import asm
from struct import unpack
import sys
# memory address where emulation starts
ADDRESS = 0x1000000
STACK_BASE = 0xf7000000
LIB_BASE = 0x7f000000
STACK_SIZE = 200 * 1024 * 1024
DEST = 0x0
get_eax = lambda :mu.reg_read(UC_X86_REG_EAX)
get_ebx = lambda :mu.reg_read(UC_X86_REG_EBX)
get_ecx = lambda :mu.reg_read(UC_X86_REG_ECX)
get_edx = lambda :mu.reg_read(UC_X86_REG_EDX)

def align(n):
    ret = 0x0;
    while ret < n:
        ret += 0x1000
    return ret

def init(payload, lib, base):
    LIB_SIZE = align(len(lib))

    # initialize unicorn emulator
    mu = Uc(UC_ARCH_X86, UC_MODE_32)
    mu.mem_map(ADDRESS, 0x1000)
    mu.mem_map(base, LIB_SIZE)
    mu.mem_map(STACK_BASE, STACK_SIZE)
    mu.mem_map(DEST, 0x1000)

    mu.reg_write(UC_X86_REG_ESP, STACK_BASE + STACK_SIZE / 2)
    mu.mem_write(ADDRESS, asm('ret'))
    mu.mem_write(base, lib)
    mu.mem_write(mu.reg_read(UC_X86_REG_ESP), payload)
    return mu

def execROPChain(payload, lib, base, output=False):
    mu = init(payload, lib, base)
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

    if output:
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

    return {
        eax: r_eax,
        ebx: r_ebx,
        ecx: r_ecx,
        edx: r_edx,
        ebp: r_ebp,
        esp: r_esp,
        edi: r_edi,
        esi: r_esi,
    }
