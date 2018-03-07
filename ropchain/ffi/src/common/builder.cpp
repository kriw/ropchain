#include "builder.h"
#include "util.h"
#include "config.h"
#include "solver.h"

//TODO
OptROP Builder::cdecl(uint64_t funcAddr, const std::vector<uint64_t>& args,
        const Gadgets& gadgets, uint64_t base, const std::set<char>& avoids) {
    auto rop = ROPChain(funcAddr);
    const size_t remainNum = args.size();
    const auto popN = Util::findByUseStack(gadgets, remainNum * Config::Arch::word());
    if(!popN.has_value()) {
        return {};
    }
    rop += ROPChain(popN.value());
    return std::accumulate(args.begin(), args.end(), rop,
            [](ROPChain a, uint64_t b) {return a + ROPChain(b);});
}

OptROP Builder::fastcall(uint64_t funcAddr, const std::vector<uint64_t>& args,
        const Gadgets& gadgets, uint64_t base, const std::set<char>& avoids) {
    std::vector<RegType::Reg> argRegs;
    if(Config::getArch() == Config::Arch::X86) {
        argRegs = std::vector<RegType::Reg>({
                RegType::ecx, RegType::edx
                });
    } else if(Config::getArch() == Config::Arch::AMD64) {
        argRegs = std::vector<RegType::Reg>({
                RegType::rdi, RegType::rsi, RegType::rdx,
                RegType::rcx, RegType::r8, RegType::r9
                });
    }
    std::map<RegType::Reg, uint64_t> dests;
    for(uint32_t i = 0; i < args.size() && i < argRegs.size(); i++) {
        dests[argRegs[i]] = args[i];
    }
    const size_t remainNum = argRegs.size() < args.size()
        ? args.size() - argRegs.size()
        : 0;
    auto remainArgs = ROPChain();
    for(uint32_t i = argRegs.size(); i < args.size(); i++) {
        remainArgs += ROPChain(args[i]);
    }
    const auto rop = Solver::solveWithGadgets(dests, gadgets, base, avoids);
    if(!rop.has_value()) {
        return {};
    }
    //TODO Impl popN gadgets
    const auto popN = Util::findByUseStack(gadgets, remainNum * Config::Arch::word());
    if(!popN.has_value()) {
        return {};
    }
    return rop.value() + ROPChain(funcAddr) + ROPChain(popN.value()) + remainArgs;
}

OptROP Builder::syscall(const std::map<RegType::Reg, uint64_t>& dests,
        const Gadgets& gadgets, uint64_t base, const std::set<char>& avoids) {
    auto rop = Solver::solveWithGadgets(dests, gadgets, base, avoids);
    OptGadget syscall = {};
    if(Config::getArch() == Config::Arch::X86) {
        syscall = Util::find(gadgets, RegSet(), "int 0x80");
    } else if(Config::getArch() == Config::Arch::AMD64) {
        syscall = Util::find(gadgets, RegSet(), "syscall");
    }
    if(!rop.has_value() || !syscall.has_value()) {
        return {};
    }
    return rop.value() + ROPChain(syscall.value());
}
