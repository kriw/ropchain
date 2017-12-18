#pragma once
#include "../util.h"
#include "../ropchain.h"
#include "../regs.h"
namespace Pop {
    OptROP find(RegType::Reg op1, const uint64_t dest,
            const Gadgets& gadgets, RegSet& aval);
};
