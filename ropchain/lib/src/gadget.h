#pragma once
#include <string>
#include <vector>
#include <optional>
#include <set>
#include "regs.h"

typedef std::string Mnem;
typedef std::variant<uint64_t, Reg> Opcode;

class Insn {
    Mnem mnem;
    std::vector<Opcode> ops;
};

class Gadget {
public:
    Gadget(uint64_t _addr, std::vector<Insn> _insns);
    bool isChanged(Reg reg);
    bool isAvailable(std::set<RegType::Reg> reg);
    std::string toString();
    bool operator==(const Gadget& gadget);
    bool operator!=(const Gadget& gadget);
private:
    std::vector<Insn> insns;
    uint64_t addr;
    //how many byte will be added to esp/rsp
    uint32_t useStack;
    //registers which will be changed its value
    std::set<RegType::Reg> changedRegs;
};

typedef std::vector<Gadget> Gadgets;

namespace GadgetUtil {
    Gadget find(Gadgets gadgets, RegSet avl, Mnem mnem, 
            std::optional<Opcode> op1,
            std::optional<Opcode> op2,
            std::optional<Opcode> op3);
    RegType::Reg findRegType(Reg reg);
    std::set<RegType::Reg> listChangedRegs(std::vector<Insn> insns);
    size_t calcUseStack(std::vector<Insn> insns);
}
