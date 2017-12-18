#pragma once
#include "../util.h"
#include "../ropchain.h"
#include "../regs.h"
namespace Neg {
    OptROP find(const RegType::Reg op1, const uint64_t dest,
            const Gadgets& gadgets, RegSet& aval);
};
