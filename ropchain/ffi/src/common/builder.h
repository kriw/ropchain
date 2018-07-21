#pragma once
#include "gadget.h"
#include "regs.h"
#include "ropchain.h"

namespace Builder {
OptROP fastcall(uint64_t funcAddr, const std::vector<uint64_t> &args,
                const Gadgets &gadgets, uint64_t base,
                const std::set<char> &avoids);
OptROP cdecl(uint64_t funcAddr, const std::vector<uint64_t> &args,
             const Gadgets &gadgets, uint64_t base,
             const std::set<char> &avoids);
OptROP syscall(const std::map<RegType::Reg, uint64_t> &dests,
               const Gadgets &gadgets, uint64_t base,
               const std::set<char> &avoids);
}; // namespace Builder
