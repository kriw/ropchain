#pragma once
#include <algorithm>
#include <map>
#include <string>
#include <vector>
#include "ropchain.h"
#include "regs.h"

#ifdef _DEBUG
template<typename T>
void ERR(T&& x) {
    std::cerr << std::forward<T>(x) << std::endl;
}

template<typename T, typename ...S>
void ERR(T&& x, S&& ...xs) {
        std::cerr << std::forward<T>(x);
        ERR(std::forward<S>(xs)...);
}
#else
#define UNUSED(x) (void)(x)
template<typename T, typename ...S>
void ERR(T&& x, S&& ...xs) {UNUSED(x);};
#endif

namespace Util {
    RegSet allRegs();
    RegSet map2Regs(const std::map<RegType::Reg, uint64_t>& m);
    std::optional<Gadget> parseGadgetString(const uint64_t addr, const std::string& gadgetStr);
    std::vector<std::string> split(const std::string& s, const std::string& delims);
    std::optional<uint64_t> toInt(const std::string& s);
    void trim(std::string& s, const std::string& delims);
    std::string join(const std::vector<std::string>& s, const std::string& separator);
    OptROP toOptROP(const std::optional<ROPElem>& gadget);
    std::vector<RegType::Reg> toBits(const RegSet& s);
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
    OptGadget find(const Gadgets& gadgets, const RegSet& avl, const Mnem& mnem);
    OptGadget find(const Gadgets& gadgets, const RegSet& avl, const Mnem& mnem, 
            const Operand op1);
    OptGadget find(const Gadgets& gadgets, const RegSet& avl, const Mnem& mnem, 
            const Operand op1, const Operand op2);
    OptGadget find(const Gadgets& gadgets, const RegSet& avl, const Mnem& mnem, 
            const std::optional<Operand> op1, const std::optional<Operand> op2,
            const std::optional<Operand> op3);
    OptGadget findByUseStack(const Gadgets& gadgets, const size_t useStack);
    RegType::Reg findRegType(const RegType::Reg reg);
    RegSet listChangedRegs(const Insn& insn);
    RegSet listChangedRegs(const Insns& insns);
    size_t calcUseStack(const Insns& insns);
    std::string intToHex(uint64_t v);
    std::string pack(uint64_t v);
    template<typename T>
    std::optional<T> minOpt(std::optional<T> a, std::optional<T> b) {
            if(!a.has_value()) {
                return b;
            }
            if(!b.has_value()) {
                return a;
            }
            return a.value() > b.value() ? b : a;
        }
    Gadgets uniqGadgets(Gadgets gadgets);
    void resetMemo();
};
