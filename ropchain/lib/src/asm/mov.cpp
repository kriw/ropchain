#include "mov.h"

OptROP Mov::find(const Opcode& op1, const Opcode& op2,
        const uint64_t dest, const Gadgets& gadgets, RegSet& aval) {
    auto gadget = Util::find(gadgets, aval, "mov", op1, op2);
    return Util::toOptROP(gadget);
}
