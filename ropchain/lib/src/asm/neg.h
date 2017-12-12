#include "../gadget.h"
#include "../regs.h"

namespace Pop {
    Gadget find(RegType::Reg r, uint64_t dest,
            Gadgets gadgets, RegSet aval);
}
