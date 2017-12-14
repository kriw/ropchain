#include "neg.h"

OptROP Neg::find(const RegType::Reg op1, const uint64_t dest,
        const Gadgets& gadgets, RegSet& aval) {
    auto gadget = Util::find(gadgets, aval, "neg", op1);
    return Util::toOptROP(gadget);
}
