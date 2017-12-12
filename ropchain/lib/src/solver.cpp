#include <optional>
#include <map>
#include <functional>
#include "ropchain.h"
#include "gadget.h"

typedef std::optional<ROPChain> OptROP;
typedef const std::function<bool(uint64_t)>& Cond;
typedef const std::function<OptROP(const Reg, const uint64_t,
        const Gadgets&, RegSet)> Proc;

OptROP _solve(const std::map<Reg, uint64_t>& dests, const Gadgets& gadgets,
        uint64_t base, Cond cond, Proc proc) {
    //TODO
    return {};
}

OptROP solveWithFile(const std::map<Reg, uint64_t>& dests, const std::string& file,
        uint64_t base, const std::set<char>& avoids) {
    //TODO
    return {};
}

OptROP solveWithGadget(const std::map<Reg, uint64_t>& dests, const Gadgets& gadgets,
        const uint64_t base, const std::set<char>& avoids) {
    //TODO
    return {};
}

OptROP solveAvoidChars(const std::map<Reg, uint64_t>& dests, const Gadgets& gadgets,
        const uint64_t base, const std::set<char>& avoids) {
    //TODO
    auto cond = [](uint64_t value) {
        return false;
    };
    Proc proc = [](const Reg reg, const uint64_t base,
            const Gadgets& gadgets, RegSet availables) {
        return ROPChain(Gadget(0, std::vector<Insn>()), 0, 0);
    };
    return _solve(dests, gadgets, base, cond, proc);
}

OptROP find(const Reg reg, const uint64_t dest, const Gadgets& gadgets,
        RegSet availables, Cond& cond, Proc& proc) {
    //TODO
    return {};
}

int main() {
    printf("Hello, world!\n");
    return 0;
}
