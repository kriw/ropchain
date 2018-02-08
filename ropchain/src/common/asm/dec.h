#pragma once
#include "../util.h"
#include "../ropchain.h"
#include "../regs.h"
namespace Dec {
    OptROP find(RegType::Reg op, const Gadgets& gadgets, RegSet& aval);
};
