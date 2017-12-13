#include "dec.h"

OptROP Dec::find(RegType::Reg op1, const uint64_t dest,
        const Gadgets& gadgets, RegSet& aval) {
    auto gadget = GadgetUtil::find(gadgets, aval, "dec", op1);
    return GadgetUtil::toOptROP(gadget);
}
