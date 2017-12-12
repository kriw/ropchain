#include "../ropchain.h"
#include "../regs.h"

namespace Pop {
    ROPChain find(RegType::Reg r, uint64_t dest,
            ROPChains ropchains, RegSet aval);
}
