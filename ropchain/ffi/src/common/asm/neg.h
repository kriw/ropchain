#pragma once
#include "../regs.h"
#include "../ropchain.h"
#include "../util.h"
namespace Neg {
OptROP find(const RegType::Reg op1, const Gadgets &gadgets, RegSet &aval);
};
