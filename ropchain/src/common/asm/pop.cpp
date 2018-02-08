#include <utility>
#include "../config.h"
#include "pop.h"
#include "add.h"
#include "inc.h"
#include "xor.h"
#include "mov.h"
#include "xchg.h"

OptROP fromIncAdd(const RegType::Reg reg, const uint64_t dest,
        const Gadgets& gadgets, RegSet& aval);
OptROP fromOtherReg(const RegType::Reg reg, const uint64_t dest,
        const Gadgets& gadgets, RegSet& aval);

OptROP Pop::find(RegType::Reg op1, const uint64_t dest,
        const Gadgets& gadgets, RegSet& aval) {
    const auto gadget = Util::find(gadgets, aval, "pop", op1);
    auto rop = gadget.has_value() 
        ?  Util::toOptROP(std::make_pair(gadget.value(), dest))
        :  (std::optional<ROPChain>){};
    rop = Util::minOpt(rop, fromIncAdd(op1, dest, gadgets, aval));
    rop = Util::minOpt(rop, fromOtherReg(op1, dest, gadgets, aval));
    return rop;
}

//xor reg, reg; ret; ([inc reg], add reg, reg)* ;ret
OptROP fromIncAdd(const RegType::Reg reg, const uint64_t dest,
        const Gadgets& gadgets, RegSet& aval) {
    const auto zero = Xor::find(reg, reg, gadgets, aval);
    const auto inc = Inc::find(reg, gadgets, aval);
    const auto _double = Add::find(reg, reg, gadgets, aval);
    if(!zero.has_value() || !inc.has_value() || !_double.has_value()) {
        return {};
    }
    auto ret = zero.value();
    for(int i = Config::Arch::bits() - 1; i > 0; i--) {
        if((dest >> i) & 1) {
            ret += inc.value();
        }
        ret += _double.value();
    }
    if(dest & 1) {
        ret += inc.value();
    }
    return ret;
}

//pop other; ret; mov reg, other; ret
//pop other; ret; xchg reg, other; ret
OptROP fromOtherReg(const RegType::Reg reg, const uint64_t dest,
        const Gadgets& gadgets, RegSet& aval) {
    const auto bits = Util::toBits(aval);
    for(const auto r : *bits) {
        if(r == reg) {
            continue;
        }
        aval.reset(reg);
        const auto pop = Pop::find(r, dest, gadgets, aval);
        aval.set(reg);
        aval.reset(r);
        const auto mov = Mov::find(reg, r, gadgets, aval);
        if(pop.has_value() && mov.has_value()) {
            aval.set(r);
            return pop.value() + mov.value();
        }
        if(pop.has_value()) {
            if(const auto xchg = Xchg::find(reg, r, gadgets, aval)) {
                aval.set(r);
                return pop.value() + xchg.value();
            }
        }
        aval.set(r);
    }
    delete bits;
    return {};
}