#include <string>
#include <vector>
#include <optional>
#include "regs.h"

typedef std::string Mnem;
typedef std::variant<uint64_t, Reg> Op;

class Insn {
    Mnem mnem;
    std::vector<Op> ops;
};

class Gadget {
    std::vector<Insn> insns;
    uint64_t addr;
    uint64_t base;
    //how many byte adding esp/rsp
    uint32_t useStack;
    //registers which will be changed its value
    std::set<Reg> changedRegs;
}

typedef std::vector<Gadget> Gadgets;
namespace Gadgets {
    Gadget find(Gadgets gadgets, std::set<Reg> avl, Mnem mnem, 
            std::optional<Op> op1,
            std::optional<Op> op2,
            std::optional<Op> op3);
}
