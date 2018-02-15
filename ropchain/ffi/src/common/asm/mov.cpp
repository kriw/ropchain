#include "mov.h"
#include "xor.h"
#include "or.h"
#include "xchg.h"
#include "lea.h"

OptROP fromLea(const Operand& op1, const Operand& op2, const Gadgets& gadgets, RegSet& aval);
OptROP fromLeaWithOffset(const Operand& op1, const Operand& op2, const Gadgets& gadgets, RegSet& aval);
OptROP fromXorXor(const Operand& op1, const Operand& op2, const Gadgets& gadgets, RegSet& aval);
OptROP fromXorOr(const Operand& op1, const Operand& op2, const Gadgets& gadgets, RegSet& aval);
OptROP fromXchg(const Operand& op1, const Operand& op2, const Gadgets& gadgets, RegSet& aval);

OptROP findWithoutXchg(const Operand& op1, const Operand& op2, const Gadgets& gadgets, RegSet& aval) {
    const auto gadget = Util::find(gadgets, aval, "mov", op1, op2);
    auto rop = Util::toOptROP(gadget);
    rop = Util::optMin(rop, fromLea(op1, op2, gadgets, aval));
    rop = Util::optMin(rop, fromLeaWithOffset(op1, op2, gadgets, aval));
    rop = Util::optMin(rop, fromXorXor(op1, op2, gadgets, aval));
    rop = Util::optMin(rop, fromXorOr(op1, op2, gadgets, aval));
    return rop;
}

OptROP Mov::find(const Operand& op1, const Operand& op2,
        const Gadgets& gadgets, RegSet& aval) {
    auto rop = findWithoutXchg(op1, op2, gadgets, aval);
    rop = Util::optMin(rop, fromXchg(op1, op2, gadgets, aval));
    return rop;
}

//lea r1, [r2]; ret
OptROP fromLea(const Operand& op1, const Operand& op2, const Gadgets& gadgets, RegSet& aval) {
    auto tmp = Insn::memRef(op2, 0);
    if(!tmp.has_value()) {
        return {};
    }
    return Lea::find(op1, tmp.value(), gadgets, aval);
}

//xor r1, r1; ret; or r1, r2; ret
OptROP fromXorOr(const Operand& op1, const Operand& op2, const Gadgets& gadgets, RegSet& aval) {
    const auto xorR1R2 = Xor::find(op1, op2, gadgets, aval);
    if(!xorR1R2.has_value()) {
        return {};
    }
    if(const auto orR1R2 = Or::find(op1, op2, gadgets, aval)) {
        return xorR1R2.value() + orR1R2.value();
    }
    return {};
}

//lea r1, [r2+imm]; ret; (dec r1; ret)*
OptROP fromLeaWithOffset(const Operand& op1, const Operand& op2, const Gadgets& gadgets, RegSet& aval) {
    // auto tmp = Insn::memRef(op2, 0);
    // if(!tmp.has_value()) {
    //     return {};
    // }
    // const auto rop = Lea::find(op1, tmp.value(), gadgets, aval);
    // return rop;
    ERR("unimplemented");
    return {};
}

//xor r1, r1; ret; xor r1, r2; ret
OptROP fromXorXor(const Operand& op1, const Operand& op2, const Gadgets& gadgets, RegSet& aval) {
    const auto xorR1R1 = Xor::find(op1, op1, gadgets, aval);
    if(!xorR1R1.has_value()) {
        return {};
    }
    if(const auto xorR1R2 = Xor::find(op1, op2, gadgets, aval)) {
        return xorR1R1.value() + xorR1R2.value();
    }
    return {};
}

//xchg r1, r2; ret mov r2, r1; ret; xchg r1, r2; ret
OptROP fromXchg(const Operand& op1, const Operand& op2, const Gadgets& gadgets, RegSet& aval) {
    const auto xchg = Xchg::find(op1, op2, gadgets, aval);
    if(!xchg.has_value()) {
        return {};
    }
    if(const auto mov = findWithoutXchg(op2, op1, gadgets, aval)) {
        return xchg.value() + mov.value() + xchg.value();
    }
    return {};
}
