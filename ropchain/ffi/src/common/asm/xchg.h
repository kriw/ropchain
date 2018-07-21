#pragma once
#include "../regs.h"
#include "../ropchain.h"
#include "../util.h"
namespace Xchg {
OptROP find(const Operand &op1, const Operand &op2, const Gadgets &gadgets,
            RegSet &aval);
};
