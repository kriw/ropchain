#pragma once
#include "../regs.h"
#include "../ropchain.h"
#include "../util.h"
namespace Inc {
OptROP find(RegType::Reg op1, const Gadgets &gadgets, RegSet &aval);
};
