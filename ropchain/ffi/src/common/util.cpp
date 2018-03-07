#include <algorithm>
#include <memory>
#include <sstream>
#include <numeric>
#include "util.h"
#include "config.h"

OptROP Util::toOptROP(const std::optional<ROPElem>& gadget) {
    if(gadget.has_value()) {
        return ROPChain(gadget.value());
    }
    return {};
}

std::optional<Gadget> Util::parseGadgetString(const uint64_t addr, const std::string& gadgetStr) {
    std::string s = gadgetStr;
    Gadgets gadgets;
    std::vector<Insn> insns;
    Util::trim(s, " ;\n");
    auto opcodes = Util::split(s, ";");
    bool canPush = true;
    for(auto& opcode : opcodes) {
        Util::trim(opcode, " \n");
        if(opcode.empty()) {
            continue;
        }
        const auto insn = Insn::fromString(opcode);
        if(!insn.has_value()) {
            canPush = false;
            break;
        }
        insns.push_back(insn.value());
    }
    if(canPush) {
        return Gadget(addr, insns);
    }
    return {};
}

std::vector<std::string> Util::split(const std::string& s, const std::string& delims) {
    std::vector<std::string> ret;
    char *buf = (char *)malloc(s.length() + 1);
    strcpy(buf, s.c_str());
    buf[s.length()] = '\0';
    const auto next = [&buf, &delims]() {
        return std::strtok(NULL, delims.c_str());
    };
    for(char *p = std::strtok(buf, delims.c_str()); p; p = next()) {
        ret.push_back(std::string(p));
    }
    free(buf);
    return ret;
}

std::optional<uint64_t> Util::toInt(const std::string& s) {
    if(2 < s.length() && s.substr(0, 2) == "0x") {
        return std::stoul(s, 0, 16);
    }
    if(0 < s.length() && '0' <= s[0] && s[0] <= '9') {
        return std::stoul(s);
    }
    return {};
}

std::string Util::join(const std::vector<std::string>& s, const std::string& separator) {
    std::ostringstream oss;
    if(!s.size()) {
        return "";
    }
    for(size_t i=0; i<s.size()-1; i++) {
        oss << s[i] << separator;
    }
    oss << s.back();
    return oss.str();
}

inline void ltrim(std::string& s, const std::string& delims) {
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), [&](int ch) {
                return delims.find(ch) == std::string::npos;
                }));
}

inline void rtrim(std::string& s, const std::string& delims) {
    s.erase(std::find_if(s.rbegin(), s.rend(), [&](int ch) {
                return delims.find(ch) == std::string::npos;
                }).base(), s.end());
}

void Util::trim(std::string& s, const std::string& delims) {
    ltrim(s, delims);
    rtrim(s, delims);
}

std::vector<RegType::Reg> Util::toBits(const RegSet& s) {
    auto bits = std::vector<RegType::Reg>();
    for(size_t i=0; i < s.size(); i++) {
        if(s.test(i)) {
            bits.push_back(i);
        }
    }
    return bits;
}

OptGadget Util::find(const Gadgets& gadgets, const RegSet& avl,
        const Mnem& mnem) {
    return find(gadgets, avl, mnem, {}, {}, {});
}

OptGadget Util::find(const Gadgets& gadgets, const RegSet& avl,
        const Mnem& mnem, const Operand op1) {
    return find(gadgets, avl, mnem, op1, {}, {});
}

OptGadget Util::find(const Gadgets& gadgets, const RegSet& avl,
        const Mnem& mnem, const Operand op1, const Operand op2) {
    return find(gadgets, avl, mnem, op1, op2, {});
}

//XXX
static std::map<size_t, Gadget> findMemo;
OptGadget Util::find(const Gadgets& gadgets, const RegSet& avl,
        const Mnem& mnem, const std::optional<Operand> op1,
        const std::optional<Operand> op2,
        const std::optional<Operand> op3) {
    auto ops = std::vector<Operand>();
    if(op1.has_value()) {
        ops.push_back(op1.value());
    }
    if(op2.has_value()) {
        ops.push_back(op2.value());
    }
    if(op3.has_value()) {
        ops.push_back(op3.value());
    }
    const Insn insn(mnem, ops);
    auto check = [&insn, &avl](auto& gadget) {
        return gadget.isAvailable(avl) && insn == gadget.insns[0];
    };
    if(findMemo.find(insn.hash) != findMemo.end()
            && check(findMemo[insn.hash])) {
        return findMemo[insn.hash];
    }
    for(const auto& gadget : gadgets) {
        if(!gadget.insns.size()) {
            continue;
        }
        if(check(gadget)) {
            return findMemo[insn.hash] = gadget;
        }
    }
    return {};
}

//Find pop N gadget or equivalent one
OptGadget Util::findByUseStack(const Gadgets& gadgets, const size_t useStack) {
    for(const auto& gadget : gadgets) {
        if(gadget.useStack == useStack) {
            return gadget;
        }
    }
    return {};
}

RegType::Reg Util::findRegType(const RegType::Reg reg) {
    if(Config::getArch() == Config::Arch::X86
            && RegType::x86RegMap.find(reg) != RegType::x86RegMap.end()) {
        return RegType::x86RegMap.at(reg);
    } else if(Config::getArch() == Config::Arch::AMD64
            && RegType::x64RegMap.find(reg) != RegType::x64RegMap.end()) {
        return RegType::x64RegMap.at(reg);
    }
    return RegType::none;
}

RegSet Util::listChangedRegs(const Insn& insn) {
    RegSet regs;
    if(insn.ops.size() > 0) {
        if(const auto r = std::get_if<RegType::Reg>(&insn.ops[0])) {
            regs.set(*r);
        } else {
            ERR("Error: Unknown Register");
        }
    }
    if(insn.mnem == "xchg") {
        if(const auto r = std::get_if<RegType::Reg>(&insn.ops[0])) {
            regs.set(*r);
        } else {
            ERR("Error: Unknown Register");
        }
        if(const auto r = std::get_if<RegType::Reg>(&insn.ops[1])) {
            regs.set(*r);
        } else {
            ERR("Error: Unknown Register");
        }
    }
    return regs;
}

RegSet Util::listChangedRegs(const Insns& insns) {
    RegSet regs;
    bool isFirst = true;
    for(const auto& insn : insns) {
        if(!isFirst && insn.ops.size() > 0) {
            if(const auto r = std::get_if<RegType::Reg>(&insn.ops[0])) {
                regs.set(*r);
            } else {
                ERR("Error: Unknown Register");
            }
        }
        if(insn.mnem == "xchg") {
            if(!isFirst) {
                if(const auto r = std::get_if<RegType::Reg>(&insn.ops[0])) {
                    regs.set(*r);
                } else {
                    ERR("Error: Unknown Register");
                }
            }
            if(const auto r = std::get_if<RegType::Reg>(&insn.ops[1])) {
                regs.set(*r);
            } else {
                ERR("Error: Unknown Register");
            }
        }
        isFirst = false;
    }
    return regs;
}

size_t _calcUseStack(const Insn& insn) {
    const auto mnem = insn.mnem;
    const auto ops = insn.ops;
    if(mnem == "pop") {
        return Config::Arch::word();
    } else if(mnem == "popad") {
        return Config::Arch::word() * 7;
    } else if(mnem == "add") {
        if(const auto r = std::get_if<RegType::Reg>(&ops[0])) {
            if(*r == RegType::esp || *r == RegType::rsp) {
                return std::get<uint64_t>(ops[1]);
            }
        }
    }
    return 0;
}

size_t Util::calcUseStack(const Insns& insns) {
    return std::accumulate(insns.begin(), insns.end(), 0,
            [](auto a, auto b) {return a + _calcUseStack(b);});
}

RegSet Util::map2Regs(const std::map<RegType::Reg, uint64_t>& m) {
    RegSet s;
    for(const auto& kv : m) {
        s.set(kv.first);
    }
    return s;
}

RegSet Util::allRegs() {
    RegSet s;
    if(Config::getArch() == Config::Arch::X86) {
        s.set(RegType::eax);
        s.set(RegType::ebx);
        s.set(RegType::ecx);
        s.set(RegType::edx);
        s.set(RegType::esi);
        s.set(RegType::edi);
        s.set(RegType::ebp);
        return s;
    }
    if(Config::getArch() == Config::Arch::AMD64) {
        s.set(RegType::rax);
        s.set(RegType::rbx);
        s.set(RegType::rcx);
        s.set(RegType::rdx);
        s.set(RegType::rdi);
        s.set(RegType::rsi);
        s.set(RegType::rbp);
        //TODO Toggle use of rsp, r8 ~ r15 by option
        // s.set(RegType::rsp);
        // s.set(RegType::r8);
        // s.set(RegType::r9);
        // s.set(RegType::r10);
        // s.set(RegType::r11);
        // s.set(RegType::r12);
        // s.set(RegType::r13);
        // s.set(RegType::r14);
        // s.set(RegType::r15);
        return s;
    }
    return RegSet();
}

std::string Util::intToHex(uint64_t v) {
    std::stringstream st;
    st << "0x";
    st << std::hex << v;
    return st.str();
}

std::string Util::pack(uint64_t v) {
    std::string ret;
    const size_t bytes = Config::Arch::word();
    for(size_t i=bytes; i > 0; i--) {
        ret += (char)(v & 0xff);
        v >>= 8;
    }
    return ret;
}

void Util::resetMemo() {
    findMemo.clear();
}

Gadgets Util::uniqGadgets(Gadgets gadgets) {
    sort(gadgets.begin(), gadgets.end());
    auto ret = Gadgets();
    for(const auto& g1 : gadgets) {
        const size_t s1 = g1.insns.size();
        bool found = false;
        for(const auto& g2 : ret) {
            const size_t s2 = g2.insns.size();
            if(s1 > s2) {
                continue;
            }
            if(s1 < s2) {
                break;
            }
            found = found || (s1 == s2 && g1 == g2);
        }
        if(!found) {
            ret.push_back(g1);
        }
    }
    return ret;
}
