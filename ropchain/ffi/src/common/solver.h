#include <optional>
#include <map>
#include <functional>
#include <numeric>
#include "ropchain.h"
#include "gadget.h"
#include "util.h"
#include "middle/middle.h"

typedef const std::function<bool(uint64_t)> Cond;
typedef const std::function<OptROP(const RegType::Reg, const uint64_t,
        const Gadgets&, const std::set<char>&, RegSet)> Proc;

namespace Solver {
    OptROP _solve(const std::map<RegType::Reg, uint64_t>& dests, const Gadgets& gadgets,
            uint64_t base, Cond& cond, Proc& proc, const std::set<char>& avoids);
    OptROP solveAvoidChars(const std::map<RegType::Reg, uint64_t>& dests, const Gadgets& gadgets,
            const uint64_t base, const std::set<char>& avoids);
    OptROP solveWithGadgets(const std::map<RegType::Reg, uint64_t>& dests, const Gadgets& gadgets,
            const uint64_t base, const std::set<char>& avoids);
    OptROP solveWithFile(const std::map<RegType::Reg, uint64_t>& dests, const std::string& file,
            uint64_t base, const std::set<char>& avoids);
    OptROP solveWithMap(const std::map<RegType::Reg, uint64_t>& dests,
            const std::map<uint64_t, std::string> insnStr,
            uint64_t base, const std::set<char>& avoids);
    OptROP findROPChain(const RegType::Reg reg, const uint64_t dest,
            const Gadgets& gadgets, RegSet aval, std::optional<Cond> cond,
            std::optional<Proc> proc, const std::set<char>& avoids);
}
