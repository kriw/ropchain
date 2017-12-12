#include "../ropchain.h"
#include "../regs.h"

namespace Xor {
    ROPChain find(RegType::Reg r1, RegType::Reg r2,
            uint64_t dest, ROPChains ropchains, RegSet aval);
}
