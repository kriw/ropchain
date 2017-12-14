#include <optional>
#include <map>
#include <functional>
#include "ropchain.h"
#include "gadget.h"
#include "util.h"
#include "middle/middle.h"

typedef const std::function<bool(uint64_t)>& Cond;
typedef const std::function<OptROP(const RegType::Reg, const uint64_t,
        const Gadgets&, RegSet)> Proc;

OptROP findROPChain(const RegType::Reg reg, const uint64_t dest,
        const Gadgets& gadgets, RegSet aval, Cond& cond, Proc& proc);

OptROP _solve(const std::map<RegType::Reg, uint64_t>& dests, const Gadgets& gadgets,
        uint64_t base, Cond& cond, Proc& proc) {
    auto regs = Util::allRegs();

    auto ropChains = std::map<RegType::Reg, ROPChain>();
    auto solvables = RegSet();
    auto remains = regs;
    for(const auto& kv : dests) {
        auto reg = kv.first;
        auto v = kv.second;

// OptROP find(const RegType::Reg reg, const uint64_t dest,
//         const Gadgets& gadgets, RegSet aval,
//         Cond& cond, Proc& proc) {
 
        auto rop = findROPChain(reg, v, gadgets, RegSet(RegType::none), cond, proc);
        if(rop.has_value()) {
            ropChains[reg] = rop.value();
            solvables.set(reg);
            remains.reset(reg);
        }
    }
    //TODO
    return {};
}

OptROP solveAvoidChars(const std::map<RegType::Reg, uint64_t>& dests, const Gadgets& gadgets,
        const uint64_t base, const std::set<char>& avoids) {
    //TODO
    auto cond = [](uint64_t value) {
        return false;
    };
    Proc proc = [](const RegType::Reg reg, const uint64_t base,
            const Gadgets& gadgets, RegSet availables) {
        return ROPChain(Gadget(0, std::vector<Insn>()));
    };
    return _solve(dests, gadgets, base, cond, proc);
}

OptROP solveWithGadgets(const std::map<RegType::Reg, uint64_t>& dests, const Gadgets& gadgets,
        const uint64_t base, const std::set<char>& avoids) {
    return solveAvoidChars(dests, gadgets, base, avoids);
}

OptROP solveWithFile(const std::map<RegType::Reg, uint64_t>& dests, const std::string& file,
        uint64_t base, const std::set<char>& avoids) {
    auto gadgets = Util::loadGadgets(file);
    return solveWithGadgets(dests, gadgets, base, avoids);
}

OptROP findROPChain(const RegType::Reg reg, const uint64_t dest,
        const Gadgets& gadgets, RegSet aval, Cond& cond, Proc& proc) {
    if(cond(dest)) {
        Middle::setVal(reg, dest, gadgets, aval);
    }
    return proc(reg, dest, gadgets, aval);
}

int main() {
    printf("Hello, world!\n");
    return 0;
}
