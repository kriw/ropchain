#include "and.h"

OptROP And::find(const Operand& op1, const Operand& op2,
        const uint64_t dest, const Gadgets& gadgets, RegSet& aval) {
    auto gadget = Util::find(gadgets, aval, "and", op1, op2);
    return Util::toOptROP(gadget);
}
