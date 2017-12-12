#include "../ropchain.h"
#include "../regs.h"

namespace Mov {
    ROPChain find(RegType::Reg r1, RegType::Reg r2,
            uint64_t dest, ROPChains ropchains, RegSet aval);
}
