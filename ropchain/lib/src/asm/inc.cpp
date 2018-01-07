#include "inc.h"

OptROP Inc::find(RegType::Reg op1, const Gadgets& gadgets, RegSet& aval) {
    auto gadget = Util::find(gadgets, aval, "inc", op1);
    return Util::toOptROP(gadget);
}
