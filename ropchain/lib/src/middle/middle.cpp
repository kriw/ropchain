#include "middle.h"
#include "../asm/xor.h"
#include "../asm/pop.h"

OptROP Middle::setVal(const RegType::Reg r,
        const uint64_t dest, const Gadgets& gadgets,
        RegSet& aval) {
    auto rop = Pop::find(r, dest, gadgets, aval);
    if(dest == 0) {
        rop = Util::optMin(rop, toZero(r, gadgets, aval));
    }
    return rop;
}

OptROP Middle::toZero(const RegType::Reg r,
        const Gadgets& gadgets, RegSet& aval) {
    const auto rop = Xor::find(r, r, gadgets, aval);
    //TODO More patterns
    return rop;
}

