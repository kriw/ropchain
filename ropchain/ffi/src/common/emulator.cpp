// #include "emulator.h"
// #include "insn.h"
// #include "config.h"
// #include <string>
// #include <fstream>
//
// struct State {
//     //Register State
//     uint64_t hoge;
// };
//
// const uint64_t X86_STACK_ADDR = 0xbf000000;
// const uint64_t AMD64_STACK_ADDR = 0xf70000000000;
// size_t loadFile(std::string fileName, char **buf) {
//     std::ifstream is(fileName, std::ios::binary);
//     is.seekg (0, is.end);
//     size_t size = is.tellg();
//     is.seekg (0, is.beg);
//     if(*buf == NULL) {
//         *buf = new char [size+1];
//     }
//     is.read(*buf, size);
//     is.close();
//     return size;
// }
//
// uc_engine* initEmulator(std::string binPath, uint64_t baseAddr) {
//     uc_engine *uc;
//     uc_err err;
//     if(Config::getArch() == Config::Arch::X86) {
//         err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
//     } else if(Config::getArch() == Config::Arch::AMD64) {
//         err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
//     }
//     if(err) {
//         printf("Failed on uc_open() with error returned: %u\n", err);
//         //TODO throw exception
//     }
//
//     //init stack
//     uint64_t stackAddress = 0;
//     size_t stackSize = 0x1000;
//     if(Config::getArch() == Config::Arch::X86) {
//         stackAddress = X86_STACK_ADDR;
//     } else if(Config::getArch() == Config::Arch::AMD64) {
//         stackAddress = AMD64_STACK_ADDR;
//     }
//     uc_mem_map(uc, stackAddress, stackSize, UC_PROT_ALL);
//
//     //init binary
//     uint64_t binAddress = baseAddr;
//     char *buf = NULL;
//     const size_t binSize = loadFile(binPath, &buf);
//     uc_mem_map(uc, binAddress, binSize, UC_PROT_ALL);
//     // write machine code to be emulated to memory
//     if (uc_mem_write(uc, binAddress, buf, binSize)) {
//       printf("Failed to write emulation code to memory, quit!\n");
//       //TODO throw exception
//     }
//     return uc;
// }
//
// State emulate(const uint64_t address, const uint32_t steps) {
//     for(uint32_t i = 0; i < steps; i++) {
//     }
//     //TODO
//     return State{};
// }
//
// uint64_t _calcStackUse(const Insn& insn) {
//     //TODO
//     return 0;
// }
//
// uint64_t Emulator::calcStackUse(const Gadget& gadget) {
//     uint64_t ret = 0;
//     for(const auto &insn : gadget.insns) {
//         ret += _calcStackUse(insn);
//     }
//     return ret;
// }
