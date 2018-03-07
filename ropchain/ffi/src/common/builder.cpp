#include "builder.h"
#include "util.h"
#include "config.h"
#include "solver.h"

//TODO
OptROP cdeclCall(uint64_t funcAddr, std::vector<uint64_t> args,
        const Gadgets gadgets, uint64_t base, const std::set<char>& avoids) {
    auto rop = ROPChain(funcAddr);
    //TODO find popN gadgets
    rop += ROPChain(0x41414141);
    return std::accumulate(args.begin(), args.end(), rop,
            [](ROPChain a, uint64_t b) {return a + ROPChain(b);});
}

OptROP fastCall(uint64_t funcAddr, std::vector<uint64_t> args,
        const Gadgets gadgets, uint64_t base, const std::set<char>& avoids) {
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
    auto remainArgs = ROPChain();
    for(uint32_t i = argRegs.size(); i < args.size(); i++) {
        remainArgs += ROPChain(args[i]);
    }
    auto rop = Solver::solveWithGadgets(dests, gadgets, base, avoids);
    if(!rop.has_value()) {
        return {};
    }
    //TODO Impl popN gadgets
    auto popN = ROPChain(0x41414141);
    return rop.value() + ROPChain(funcAddr) + popN + remainArgs;
}

OptROP syscall(const std::map<RegType::Reg, uint64_t>& dests,
        const Gadgets gadgets, uint64_t base, const std::set<char>& avoids) {
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
