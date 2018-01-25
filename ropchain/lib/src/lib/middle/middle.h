#pragma once
#include "../ropchain.h"
#include "../util.h"

namespace Middle {
    OptROP setVal(const RegType::Reg r,
            const uint64_t dest, const Gadgets& gadgets,
            RegSet& aval);
    OptROP toZero(const RegType::Reg r,
            const Gadgets& gadgets, RegSet& aval);
};


