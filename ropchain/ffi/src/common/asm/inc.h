#pragma once
#include "../util.h"
#include "../ropchain.h"
#include "../regs.h"
namespace Inc {
    OptROP find(RegType::Reg op1, const Gadgets& gadgets, RegSet& aval);
};
