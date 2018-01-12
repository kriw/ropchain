#include "xchg.h"

OptROP Xchg::find(const Opcode& op1, const Opcode& op2,
        const Gadgets& gadgets, RegSet& aval) {
    if(const auto g1 = Util::find(gadgets, aval, "xchg", op1, op2)) {
        return ROPChain(g1.value());
    }
    if(const auto g2 = Util::find(gadgets, aval, "xchg", op2, op1)) {
        return ROPChain(g2.value());
    }
    return {};
}
