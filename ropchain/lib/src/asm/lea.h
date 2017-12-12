#include "../ropchain.h"
#include "../regs.h"

namespace Mov {
    Ropchain find(RegType::Reg r1, RegType::Reg r2,
            uint64_t dest, Ropchains ropchains, RegSet aval);
}
