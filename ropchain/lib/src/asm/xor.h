#pragma once
#include "../util.h"
#include "../ropchain.h"
#include "../regs.h"
namespace Xor {
    OptROP find(const Opcode& op1, const Opcode& op2,
            const Gadgets& gadgets, RegSet& aval);
};
