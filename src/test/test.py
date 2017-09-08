#!/usr/bin/env python2
# coding: UTF-8

from unicorn import *
from unicorn.x86_const import *
from struct import unpack
import sys
import commands
import subprocess

# memory address where emulation starts
ADDRESS = 0x1000000
STACK_BASE = 0x5000000

# initialize unicorn emulator
mu = Uc(UC_ARCH_X86, UC_MODE_32)
# map 4MB for this emulation
mu.mem_map(ADDRESS, 4 * 1024 * 1024)
mu.mem_map(STACK_BASE, 2 * 1024 * 1024)

get_eax = lambda :mu.reg_read(UC_X86_REG_EAX)
get_ebx = lambda :mu.reg_read(UC_X86_REG_EBX)
get_ecx = lambda :mu.reg_read(UC_X86_REG_ECX)
get_edx = lambda :mu.reg_read(UC_X86_REG_EDX)

#shellcode execve("/bin//sh")
if len(sys.argv) > 0:
    binary = sys.argv[1]
else:
    binary = b'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80'

def read_str(addr):
    global mu
    c = '_'
    string = ''
    while ord(c):
        c = str(mu.mem_read(addr, 1))
        addr += 1
        string += c
    return string[:-1]

#handle interupt
mu.hook_add(UC_HOOK_INTR, hook_intr)

mu.mem_write(ADDRESS, binary)
mu.reg_write(UC_X86_REG_ESP, STACK_BASE + 1024 * 1024)

# emulate code in infinite time & unlimited instructions
mu.emu_start(ADDRESS, ADDRESS + len(binary))

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
