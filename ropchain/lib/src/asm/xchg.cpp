#include "xchg.h"

OptROP Xchg::find(const Opcode& op1, const Opcode& op2,
        const Gadgets& gadgets, RegSet& aval) {
    auto gadget = Util::find(gadgets, aval, "xchg", op1, op2);
    return Util::toOptROP(gadget);
}
