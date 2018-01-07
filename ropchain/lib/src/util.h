#pragma once
#include <algorithm>
#include <map>
#include <string>
#include <vector>
#include "ropchain.h"
#include "regs.h"


namespace Util {
    RegSet allRegs();
    RegSet map2Regs(const std::map<RegType::Reg, uint64_t>& m);
    std::vector<std::string> split(std::string s, char delim);
    void trim(std::string& s, const std::string& delims);
    std::string join(const std::vector<std::string>& s, const std::string& separator);
    OptROP toOptROP(const OptGadget& gadget);
	std::vector<RegType::Reg> *toBits(const RegSet& s);
    Gadgets loadGadgets(const std::string& fileName);
    template <typename T>
        T optMin(T t1, T t2) {
            if(!t1.has_value()) {
                return t2;
            }
            if(!t2.has_value()) {
                return t1;
            }
            return std::min(t1.value(), t2.value());
        }
    OptGadget find(const Gadgets& gadgets, const RegSet& avl, const Mnem& mnem, 
            const Opcode op1);
    OptGadget find(const Gadgets& gadgets, const RegSet& avl, const Mnem& mnem, 
            const Opcode op1, const Opcode op2);
    OptGadget find(const Gadgets& gadgets, const RegSet& avl, const Mnem& mnem, 
            const std::optional<Opcode> op1, const std::optional<Opcode> op2,
            const std::optional<Opcode> op3);
    RegType::Reg findRegType(RegType::Reg reg);
    RegSet listChangedRegs(const Insns& insns);
    size_t calcUseStack(const Insns& insns);
	std::string pack(uint64_t v);
};
