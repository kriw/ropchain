#include "../ropchain.h"
#include "../regs.h"

namespace Mov {
    OptROP find(const Opcode& op1, const Opcode& op2,
            const uint64_t dest, const Gadgets& gadgets, RegSet& aval);
};
