#include "add.h"

OptROP Add::find(const Opcode& op1, const Opcode& op2,
        const Gadgets& gadgets, RegSet& aval) {
    auto gadget = Util::find(gadgets, aval, "add", op1, op2);
    return Util::toOptROP(gadget);
}
