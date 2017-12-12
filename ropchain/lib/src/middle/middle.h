#include "../ropchain.h"

namespace Middle {
    ROPChain setVal(RegType::Reg r, uint64_t dest,
            ROPChains ropchains, RegSet aval);
    ROPChain toZero(RegType::Reg r, uint64_t dest,
            ROPChains ropchains, RegSet aval);
};


