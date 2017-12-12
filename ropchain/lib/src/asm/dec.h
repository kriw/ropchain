#include "../ropchain.h"
#include "../regs.h"

namespace Pop {
    Ropchain find(RegType::Reg r, uint64_t dest,
            Ropchains ropchains, RegSet aval);
}
