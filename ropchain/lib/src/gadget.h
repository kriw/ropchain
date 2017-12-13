#pragma once
#include <string>
#include <vector>
#include <optional>
#include <set>
#include "regs.h"

typedef std::string Mnem;
typedef std::variant<uint64_t, Reg> Opcode;

typedef struct Insn {
    Mnem mnem;
    std::vector<Opcode> ops;
    bool operator==(const struct Insn& insn) const {
        //TODO
        return true;
        // return mnem == insn.mnem && ops == insn.ops;
    }
    bool operator!=(const struct Insn& insn) {
        return !(*this == insn);
    }
} Insn;

typedef std::vector<Insn> Insns;

class Gadget {
public:
    Gadget(uint64_t _addr, std::vector<Insn> _insns);
    bool isChanged(const RegType::Reg reg) const;
    bool isAvailable(const RegSet& reg) const;
    std::string toString() const;
    bool operator==(const Gadget& gadget) const;
    bool operator!=(const Gadget& gadget) const;
    const std::vector<Insn> getInsns() const;
private:
    std::vector<Insn> insns;
    uint64_t addr;
    //how many byte will be added to esp/rsp
    uint32_t useStack;
    //registers which will be changed its value
    RegSet changedRegs;
};

typedef std::optional<Gadget> optGadget;
typedef std::vector<Gadget> Gadgets;

namespace GadgetUtil {
    optGadget find(const Gadgets& gadgets, const RegSet& avl, const Mnem& mnem, 
            const std::optional<Opcode>& op1);
    optGadget find(const Gadgets& gadgets, const RegSet& avl, const Mnem& mnem, 
            const std::optional<Opcode>& op1, const std::optional<Opcode>& op2);
    optGadget find(const Gadgets& gadgets, const RegSet& avl, const Mnem& mnem, 
            const std::optional<Opcode>& op1, const std::optional<Opcode>& op2,
            const std::optional<Opcode>& op3);
    RegType::Reg findRegType(Reg reg);
    RegSet listChangedRegs(const Insns& insns);
    size_t calcUseStack(const Insns& insns);
};
