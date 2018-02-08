#include "movzx.h"

OptROP Movzx::find(const Operand& op1, const Operand& op2,
        const Gadgets& gadgets, RegSet& aval) {
    auto gadget = Util::find(gadgets, aval, "movzx", op1, op2);
    return Util::toOptROP(gadget);
}
