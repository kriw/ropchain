#include <optional>
#include <map>
#include "ropchain.h"

std::optional<ROPChain> _solve(std::map<Reg, uint64_t> dests,
        std::vector<Gadget> gadgets, uint64_t base,
        cond, proc) {
    //TODO
}

std::optional<ROPChain> solveAvoidChars(const std::map<Reg, uint64_t> dests,
        const std::vector<Gadget> gadgets, const uint64_t base, const std::set<char> avoids) {
    auto cond = []() {
    };
    auto proc = []() {
    };
    return _solve(dests, gadgets, base, canUse);
}
