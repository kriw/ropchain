from wrapper import solveFromDict
from ropchain import reset
from register import *
from pwn import asm
import emulator
import unittest

class TestROPChain(unittest.TestCase):
    def do(self, dests, gadgetsDict, base=emulator.LIB_BASE, avoids=[]):
        reset()
        verify = lambda xs, p: all([x not in p for x in xs])
        lib = buildFromGadgets(gadgetsDict)
        # payload = solveFromDict(dests, gadgetsDict, base, avoids).payload()
        rop = solveFromDict(dests, gadgetsDict, base, avoids)
        # rop.dump()
        payload = rop.payload()
        verify(avoids, payload)
        testResult = emulator.execROPChain(payload, lib, base)
        self.assertTrue(isCorrect(dests, testResult))

    def testPop(self):
        dests = {eax: 0x0, ebx: 0x602030, ecx: 0x1000}
        gadgets = {
                0x10000: 'pop eax; ret',
                0x20000: 'pop ebx; ret',
                0x30000: 'pop ecx; ret'
                }
        self.do(dests, gadgets)

    def testIncAdd(self):
        dests = {eax: 0x12345678}
        gadgets = {
                0x10000: 'xor eax, eax; ret',
                0x20000: 'inc eax; ret',
                0x30000: 'add eax, eax; ret'
            }
        self.do(dests, gadgets)

    def testPopMov(self):
        dests = {eax: 0x12345678, esi: 0x41414141}
        gadgets = {
                0x1000: 'pop esi; ret',
                0x2000: 'mov eax, esi; ret'
            }
        self.do(dests, gadgets)

    def testPopXchg(self):
        dests = {eax: 0x12345678, esi: 0x41414141}
        gadgets = {
                0x1000: 'pop esi; ret',
                0x2000: 'xchg eax, esi; ret'
            }
        self.do(dests, gadgets)

    def testPopMov6Regs(self):
        dests = {
            eax: 0x12345678,
            ebx: 0x87654321,
            ecx: 0x22222222,
            edx: 0x7fffffff,
            esi: 0x41414141,
            edi: 0x42424242
        }
        gadgets = {
            0x1000: 'pop esi; ret',
            0x2000: 'mov ebx, esi; ret',
            0x3000: 'mov eax, ecx; ret',
            0x4000: 'mov ecx, ebx; ret',
            0x5000: 'mov edx, esi; ret',
            0x6000: 'mov edi, eax; ret',
        }
        self.do(dests, gadgets)

    def testMovWithoutPop(self):
        dests = {eax:  0x12345678, esi:  0x41414141}
        gadgets = {
            0x1000: 'xor esi, esi; ret',
            0x2000: 'inc esi; ret',
            0x3000: 'add esi, esi; ret',
            0x4000: 'mov eax, esi; ret',
        }
        self.do(dests, gadgets)

    def testMovWithoutPop6Regs(self):
        dests = {
            eax:  0x12345678,
            ebx:  0x22222222,
            ecx:  0x33333333,
            edx:  0x87654321,
            esi:  0x41414141,
            edi:  0x42424242,
        }
        gadgets = {
            0x1000: 'xor esi, esi; ret',
            0x2000: 'inc esi; ret',
            0x3000: 'add esi, esi; ret',
            0x4000: 'mov eax, esi; ret',
            0x5000: 'mov ebx, eax; ret',
            0x6000: 'mov edx, ecx; ret',
            0x7000: 'mov edi, edx; ret',
            0x8000: 'mov ecx, ebx; ret',
        }
        self.do(dests, gadgets)

    def testPopXor(self):
        dests = {eax: 0x12345678, esi: 0x41414141}
        gadgets = {
                0x1000: 'pop esi; ret',
                0x2000: 'xor eax, eax; ret',
                0x3000: 'xor eax, esi; ret'
            }
        self.do(dests, gadgets)

    def testAscii(self):
        libBase = 0x55550000
        avoids = set([chr(i) for i in range(0x100) if not 0x20 <= i <= 0x7e])
        dests = {eax: 0x41414141, ebx: 0x41424344}
        gadgets = {
                0x5455: 'pop eax; ret',
                0x5555: 'pop ebx; ret',
                }
        self.do(dests, gadgets, libBase, avoids)

    def testAsciiXor(self):
        libBase = 0x55550000
        avoids = set([chr(i) for i in range(0x100) if not 0x20 <= i <= 0x7e])
        dests = {eax: 0xb, ebx: 0x55554444}
        gadgets = {
                0x5455: 'mov eax, ebx; ret',
                0x5555: 'xor eax, ebx; ret',
                0x5655: 'pop ebx; ret',
                }
        self.do(dests, gadgets, libBase, avoids)

    def testScanfInc(self):
        avoids = set(['\x09', '\x0a', '\x0b', '\x20'])
        dests = {eax: 0xb}
        gadgets = {
                0x5355: 'pop eax; ret',
                0x5455: 'inc eax; ret',
                0x5555: 'xor eax, eax; ret',
                }
        self.do(dests, gadgets, avoids=avoids)


    def testScanf(self):
        avoids = set(['\x09', '\x0a', '\x0b', '\x20'])
        dests = {eax: 0xb, ebx: 0x55554444}
        gadgets = {
                0x5455: 'mov eax, ebx; ret',
                0x5555: 'xor eax, ebx; ret',
                0x5655: 'pop ebx; ret',
                }
        self.do(dests, gadgets, avoids=avoids)


def buildFromGadgets(gadgets):
    addrs = gadgets.keys()
    insns = list(map(asm, gadgets.values()))
    lib = '\x00' * (max(addrs) + len(max(insns, key=len)))
    for addr, insn in zip(addrs, insns):
        lib = lib[:addr] + insn + lib[addr+len(insn):]
    return lib

def isCorrect(expected, result):
    for reg  in expected:
        if result[reg] != expected[reg]:
            return False
    return True

if __name__ == '__main__':
    unittest.main()
