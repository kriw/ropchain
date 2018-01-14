#pragma once
#include "../util.h"
#include "../ropchain.h"
#include "../regs.h"
namespace And {
    OptROP find(const Operand& op1, const Operand& op2,
            const uint64_t dest, const Gadgets& gadgets, RegSet& aval);
};
