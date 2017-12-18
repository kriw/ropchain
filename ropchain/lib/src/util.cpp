#include "util.h"

OptROP Util::toOptROP(const OptGadget& gadget) {
    if(gadget.has_value()) {
        return ROPChain(gadget.value());
    }
    return {};
}
Gadgets Util::loadGadgets(const std::string& fileName) {
    //TODO
    return std::vector<Gadget>();
}

OptGadget Util::find(const Gadgets& gadgets, const RegSet& avl,
        const Mnem& mnem, const std::optional<Opcode> op1) {
    return find(gadgets, avl, mnem, op1, {}, {});
}
OptGadget Util::find(const Gadgets& gadgets, const RegSet& avl,
        const Mnem& mnem, const std::optional<Opcode> op1,
        const std::optional<Opcode> op2) {
    return find(gadgets, avl, mnem, op1, op2, {});
}
OptGadget Util::find(const Gadgets& gadgets, const RegSet& avl,
        const Mnem& mnem, const std::optional<Opcode> op1,
        const std::optional<Opcode> op2,
        const std::optional<Opcode> op3) {
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

RegType::Reg Util::findRegType(RegType::Reg a) {
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

RegSet Util::listChangedRegs(const Insns& insns) {
    //TODO
    //r1 = {findRegKind(insn.ops[0]) for insn in insns if len(insn.ops) > 0}
    // r2 = {findRegKind(insn.ops[1]) for insn in insns if insn.mnem == 'xchg'}
    // r12 = r1 | r2
    // if None in r12:
    // r12.remove(None)
    // return r12
    return RegSet();
}

size_t Util::calcUseStack(const Insns& insns) {
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

RegSet Util::allRegs() {
	return RegSet();
}
