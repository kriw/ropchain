#include "gadget.h"

Gadget::Gadget(uint64_t _addr, std::vector<Insn> _insns) {
    addr = _addr;
    insns = _insns;
    useStack = GadgetUtil::calcUseStack(insns);
    changedRegs = GadgetUtil::listChangedRegs(insns);
}

std::string Gadget::toString() const {
    //TODO
    return "TODO";
}

bool Gadget::operator==(const Gadget& gadget) const {
    const auto _insns = gadget.getInsns();
    if(insns.size() != _insns.size()) {
        return false;
    }
    return insns == _insns;
}

bool Gadget::operator!=(const Gadget& gadget) const {
    return !(*this == gadget);
}

bool Gadget::isChanged(const RegType::Reg reg) const {
    return changedRegs.exist(reg);
}

bool Gadget::isAvailable(const RegSet& rs) const {
    return changedRegs > rs;
}

const std::vector<Insn> Gadget::getInsns() const {
    return insns;
}

namespace GadgetUtil {
    optGadget find(const Gadgets& gadgets, const RegSet& avl,
            const Mnem& mnem, const std::optional<Opcode>& op1) {
        return find(gadgets, avl, mnem, op1, {}, {});
    }
    optGadget find(const Gadgets& gadgets, const RegSet& avl,
            const Mnem& mnem, const std::optional<Opcode>& op1,
            const std::optional<Opcode>& op2) {
        return find(gadgets, avl, mnem, op1, op2, {});
    }
    optGadget find(const Gadgets& gadgets, const RegSet& avl,
            const Mnem& mnem, const std::optional<Opcode>& op1,
            const std::optional<Opcode>& op2,
            const std::optional<Opcode>& op3) {
        auto ops = std::vector<Opcode>();
        if(op1.has_value()) {
            ops.push_back(op1.value());
        }
        if(op2.has_value()) {
            ops.push_back(op2.value());
        }
        if(op3.has_value()) {
            ops.push_back(op3.value());
        }
        const Insn insn = Insn{mnem, ops};
        for(const auto& gadget : gadgets) {
            const auto insn_g = gadget.getInsns()[0];
            if(insn == insn_g && gadget.isAvailable(avl)) {
                return gadget;
            }
        }
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

    RegSet listChangedRegs(const Insns& insns) {
        //TODO
//r1 = {findRegKind(insn.ops[0]) for insn in insns if len(insn.ops) > 0}
// r2 = {findRegKind(insn.ops[1]) for insn in insns if insn.mnem == 'xchg'}
// r12 = r1 | r2
// if None in r12:
// r12.remove(None)
// return r12
        return RegSet();
    }

    size_t calcUseStack(const Insns& insns) {
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
