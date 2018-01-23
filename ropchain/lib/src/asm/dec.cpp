#include "dec.h"

OptROP Dec::find(RegType::Reg op1, const Gadgets& gadgets, RegSet& aval) {
    auto gadget = Util::find(gadgets, aval, "dec", op1);
    return Util::toOptROP(gadget);
}
