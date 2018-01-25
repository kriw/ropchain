#pragma once
#include "../util.h"
#include "../ropchain.h"
#include "../regs.h"
namespace Neg {
    OptROP find(const RegType::Reg op1, const Gadgets& gadgets, RegSet& aval);
};
