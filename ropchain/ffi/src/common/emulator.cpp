#include "emulator.h"
#include "insn.h"
#include "config.h"
#include <string>

struct State {
    //Register State
    uint64_t hoge;
};

uc_engine* initEmulator(std::string binPath) {
    //TODO load binary
    uc_engine *uc;
    uc_err err;
    if(Config::Arch::X86) {
        err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    } else if(Config::Arch::AMD64) {
        err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
    }
    if(err) {
        printf("Failed on uc_open() with error returned: %u\n", err);
        //TODO throw exception
    }
    return uc;
}

State emulate(const uint64_t address, const uint32_t steps) {
    //TODO
    return State{};
}

uint64_t _calcStackUse(const Insn& insn) {
    //TODO
    return 0;
}

uint64_t Emulator::calcStackUse(const Gadget& gadget) {
    uint64_t ret = 0;
    for(const auto &insn : gadget.insns) {
        ret += _calcStackUse(insn);
    }
    return ret;
}
