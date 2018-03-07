#pragma once
#include "ropchain.h"
#include "regs.h"

namespace Builder {
    OptROP fastCall(uint64_t funcAddr, std::vector<uint64_t> args,
            const Gadgets& gadgets, uint64_t base, const std::set<char>& avoids);
    OptROP cdeclCall(uint64_t funcAddr, std::vector<uint64_t> args,
            const Gadgets& gadgets, uint64_t base, const std::set<char>& avoids);
    OptROP syscall(const std::map<RegType::Reg, uint64_t>& dests,
            const Gadgets& gadgets, uint64_t base, const std::vector<char>& _avoids);
}
