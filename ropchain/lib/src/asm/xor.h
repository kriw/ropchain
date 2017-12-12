#include "gadget.h"
#include "regs.h"

def find(reg, dest, gadgets, canUse):
namespace Xor {
    Gadget find(RegType::Reg r1, RegType::Reg r2,
            uint64_t dest, Gadgets gadgets,
            std::set<RegType::Reg> aval);
}
