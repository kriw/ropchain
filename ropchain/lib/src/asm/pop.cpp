#include "pop.h"

OptROP Pop::find(RegType::Reg op1, const uint64_t dest,
        const Gadgets& gadgets, RegSet& aval) {
    auto gadget = GadgetUtil::find(gadgets, aval, "pop", op1);
    return GadgetUtil::toOptROP(gadget);
}
