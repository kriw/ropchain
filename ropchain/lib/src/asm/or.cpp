#include "or.h"

OptROP Or::find(const Opcode& op1, const Opcode& op2,
        const uint64_t dest, const Gadgets& gadgets, RegSet& aval) {
    auto gadget = GadgetUtil::find(gadgets, aval, "or", op1, op2);
    return GadgetUtil::toOptROP(gadget);
}
