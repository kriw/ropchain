#include "gadget.h"

Gadget::Gadget(uint64_t _addr, std::vector<Insn> _insns) {
    addr = _addr;
    insns = _insns;
    useStack = GadgetUtil::calcUseStack(insns);
    changedRegs = GadgetUtil::listChangedRegs(insns);
}

std::string Gadget::toString() {
    //TODO
    return "";
}

bool Gadget::operator==(const Gadget& gadget) {
    // if len(self.insns) != len(gadget.insns):
    //     return False
    // return all(map(lambda x, y: x == y, self.insns, gadget.insns))
    return false;
}

bool Gadget::operator!=(const Gadget& gadget) {
    return !(*this == gadget);
}

bool Gadget::isChanged(Reg reg) {
    //TODO
    // return changedRegs.find(reg.type) != changedRegs.end();
    return false;
}

namespace GadgetUtil {
    std::optional<Gadget> find(
            Gadgets gadgets,
            std::set<RegType::Reg> avl,
            Mnem mnem, 
            std::optional<Opcode> op1,
            std::optional<Opcode> op2,
            std::optional<Opcode> op3
            ) {
        //TODO
    // def find(gadgets, canUse, mnem, op1=None, op2=None, op3=None):
    // ops = list(filter(lambda x: x != None, [op1, op2, op3]))
    // insn = Insn(mnem, ops)
    // for gadget in gadgets:
    //     if gadget.insns[0] == insn and gadget.canUsed(canUse):
    //         return gadget, canUse - gadget.changedRegs
    // return None, canUse
        return {};
    }

    RegType::Reg findRegType(Reg) {
        //TODO
//     
// def findRegKind(reg):
//     reg = reg.lower().strip()
//     convReg = lambda x: x if arch.arch == arch.AMD64 else 'e' + x[1:]
//     if reg in ['rax', 'eax', 'ax', 'al', 'ah']:
//         return convReg('rax')
//     elif reg in ['rbx', 'ebx', 'bx', 'bl', 'bh']:
//         return convReg('rbx')
//     elif reg in ['rcx', 'ecx', 'cx', 'cl', 'ch']:
//         return convReg('rcx')
//     elif reg in ['rdx', 'edx', 'dx', 'dl', 'dh']:
//         return convReg('rdx')
//     elif reg in ['rdi', 'edi']:
//         return convReg('rdi')
//     elif reg in ['rsi', 'esi']:
//         return convReg('rsi')
//     elif reg in ['rbp', 'ebp']:
//         return convReg('rbp')
//     elif reg in ['rsp', 'esp']:
//         return convReg('rsp')
//     elif reg in ['r%d%s' % (i, s) for i in range(8, 16) for s in ['', 'd', 'w', 'b']]:
//         if reg[-1] in ['d', 'w', 'b']:
//             return reg[:-1]
//         return reg
//     else:
//         return None
        return RegType::rax;
    }

    std::set<RegType::Reg> listChangedRegs(std::vector<Insn> insns) {
        //TODO
//r1 = {findRegKind(insn.ops[0]) for insn in insns if len(insn.ops) > 0}
// r2 = {findRegKind(insn.ops[1]) for insn in insns if insn.mnem == 'xchg'}
// r12 = r1 | r2
// if None in r12:
// r12.remove(None)
// return r12
        return std::set<RegType::Reg>();
    }

    size_t calcUseStack(std::vector<Insn> insns) {
        //TODO
// mnem, ops = insn.mnem, insn.ops
// # print 'mnem: %s, ops: %s' % (mnem, str(ops))
// if mnem == 'pop':
//     return arch.word() * 1
// elif mnem == 'popad':
//     return arch.word() * 7
// elif mnem == 'add' and (ops[0] == 'esp' or ops[0] == 'rsp'):
//     return arch.word() * int(ops[1][2:], 16)
// else:
//     return 0
    }
}
