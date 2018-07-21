#pragma once
#include "../regs.h"
#include "../ropchain.h"
#include "../util.h"
namespace Dec {
OptROP find(RegType::Reg op, const Gadgets &gadgets, RegSet &aval);
};
