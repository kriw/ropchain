#include <iostream>
#include "regs.h"
#include "solver.h"
#include "./frontend/r2/r2_loader.h"
#include "./frontend/rp++/rp_loader.h"

int main() {
    auto gadgets = Frontend::R2::from("/bin/ls").value();
    // auto gadgets = Frontend::RPP::from("/usr/lib/libc.so.6").value();
    std::cout << gadgets.size() << std::endl;
    for(auto g : gadgets) {
        std::cout << g.toString() << std::endl;
    }
    // std::map<RegType::Reg, uint64_t> dests = {{"rax", 0x41414141}};
    auto rop = Solver::solveAvoidChars({{RegType::rdi, 0x41414141}}, gadgets, 0, {});
    if(!rop.has_value()) {
        std::cerr << "Error" << std::endl;
    }
    // rop.value().dump();
    return 0;
}
