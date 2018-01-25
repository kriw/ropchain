#include "or.h"

OptROP Or::find(const Operand& op1, const Operand& op2,
        const Gadgets& gadgets, RegSet& aval) {
    auto gadget = Util::find(gadgets, aval, "or", op1, op2);
    return Util::toOptROP(gadget);
}
