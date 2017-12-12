#include "../gadget.h"
#include "../regs.h"

namespace Mov {
    Gadget find(RegType::Reg r1, RegType::Reg r2,
            uint64_t dest, Gadgets gadgets, RegSet aval);
}
